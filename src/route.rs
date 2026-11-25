use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use ipnet::IpNet;

use crate::config::{Config, DomainStrategy, Outbound, OutboundKind, PortRange, Rule};
use crate::session::{Host, Network, Target};

#[derive(Clone, Debug)]
pub struct Router {
    default: Resolved,
    domain_strategy: DomainStrategy,
    rules: Vec<CompiledRule>,
    urltest_groups: Vec<Arc<UrltestGroup>>,
    /// 已编译的代理出站；反向 Bridge 需要按 tag 取得与普通路由相同的实例。
    proxies: HashMap<String, Arc<ProxyOutbound>>,
}

/// 展开一条规则里的地理数据引用。
///
/// 没有配置 `geo` 段时，出现 `geosite:` 等引用会直接报错——静默跳过会让
/// 用户以为规则生效了。
fn expand_geo(
    geo_data: Option<&crate::geo::GeoData>,
    rule: &Rule,
    rule_index: usize,
    budget: &mut crate::geo::ExpansionBudget,
) -> Result<crate::geo::Expanded> {
    let geo_ip_refs: Vec<String> = rule
        .ip_cidrs
        .iter()
        .filter_map(|entry| match entry {
            crate::config::IpEntry::Geo(value) => Some(value.clone()),
            crate::config::IpEntry::Cidr(_) => None,
        })
        .collect();
    let has_domain_refs = rule
        .domains
        .iter()
        .any(|value| crate::geo::code_of(value).is_some());
    if !has_domain_refs && geo_ip_refs.is_empty() {
        return Ok(crate::geo::Expanded::default());
    }
    let Some(data) = geo_data else {
        let sample = rule
            .domains
            .iter()
            .find(|value| crate::geo::code_of(value).is_some())
            .map(String::as_str)
            .or_else(|| geo_ip_refs.first().map(String::as_str))
            .unwrap_or("geosite:");
        anyhow::bail!(
            "规则引用了 {sample}，但配置里没有 geo 段；请设置 geo.geosite / geo.geoip / geo.mmdb，或改成具体值"
        );
    };
    crate::geo::expand(data, &rule.domains, &geo_ip_refs, rule_index, budget)
}

fn ipnet_of(cidr: crate::geo::Cidr) -> Result<IpNet> {
    IpNet::new(cidr.addr, cidr.prefix)
        .with_context(|| format!("地理数据里的 CIDR 无效: {}/{}", cidr.addr, cidr.prefix))
}

/// 地理展开项的运行期形态：正则在此预编译。
///
/// 真实 geosite.dat 含正则条目；每次选路重新 `Regex::new` 会在热路径上
/// 重复编译（实测 1000 次约 400 ms，预编译后约 30 μs）。
#[derive(Clone, Debug)]
enum CompiledGeoDomain {
    Full(String),
    Suffix(String),
    /// 仅子域（sing-box 的 `domain_suffix: [".a.test"]` 写法）。
    Subdomain(String),
    Keyword(String),
    Regex(regex::Regex),
}

impl CompiledGeoDomain {
    fn compile(item: &crate::geo::DomainMatcher) -> Result<Self> {
        Ok(match item {
            crate::geo::DomainMatcher::Full(value) => Self::Full(value.clone()),
            crate::geo::DomainMatcher::Suffix(value) => Self::Suffix(value.clone()),
            crate::geo::DomainMatcher::Subdomain(value) => Self::Subdomain(value.clone()),
            crate::geo::DomainMatcher::Keyword(value) => Self::Keyword(value.clone()),
            crate::geo::DomainMatcher::Regex(value) => Self::Regex(
                regex::Regex::new(value)
                    .map_err(|error| anyhow::anyhow!("地理数据里的正则 {value:?} 无效: {error}"))?,
            ),
        })
    }

    /// 语义与 `geo::DomainMatcher::matches` 一致。
    fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Full(value) => domain == value,
            Self::Suffix(value) => matches_domain_suffix(domain, value),
            Self::Subdomain(value) => domain
                .strip_suffix(value.as_str())
                .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1),
            Self::Keyword(value) => domain.contains(value.as_str()),
            Self::Regex(pattern) => pattern.is_match(domain),
        }
    }
}

/// 一条规则的求值结果。
///
/// `NeedIp` 表示「目标域名尚未解析，IP 条件无法判定」。它**不参与取反**：
/// 否则 `invert` 会把「还不知道」当成「不命中」，凭空命中一条 IP 规则。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleMatch {
    Hit,
    Miss,
    NeedIp,
}

impl RuleMatch {
    /// `invert` 只交换命中与不命中；`NeedIp` 保持未知。
    fn negate(self) -> Self {
        match self {
            Self::Hit => Self::Miss,
            Self::Miss => Self::Hit,
            Self::NeedIp => Self::NeedIp,
        }
    }
}

/// IP 维度的判定结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpOutcome {
    /// 没有任何 IP 条件。
    Always,
    /// 有 IP 条件，但集合为空（例如空分类），永远不成立。
    Never,
    /// 需要目标地址才能判定。
    NeedIp,
    /// 已判定。
    Value(bool),
}

#[derive(Clone, Debug)]
struct CompiledRule {
    inbounds: Vec<String>,
    networks: Vec<Network>,
    domains: Vec<String>,
    domain_suffix: Vec<String>,
    domain_keyword: Vec<String>,
    /// 配置期已编译；非法正则在校验阶段就被拒绝。
    domain_regex: Vec<regex::Regex>,
    ip_cidrs: Vec<IpNet>,
    ip_is_private: bool,
    /// 地理数据集展开出的域名项（正则已预编译）。
    ///
    /// 与 `domains` 组成**同一个 OR 组**：它们都来自配置的 `domains` 数组，
    /// 而 Xray 的 domain 数组内部是并集。曾经把展开项独立成 AND 字段，
    /// 导致「普通域名 + geosite」同写时两者互相要求成立、任何目标都不命中。
    geo_domains: Vec<CompiledGeoDomain>,
    /// 配置里是否出现过域名侧地理引用。即使展开结果为 0 条，也必须算作
    /// 有限制，否则空分类会退化成「匹配一切」。
    geo_domain_used: bool,
    /// `mmdb:<code>`：只能运行期按 IP 查国家码，不能预先展开成 CIDR。
    mmdb_codes: Vec<String>,
    /// 配置里是否出现过 IP 侧地理引用（同上，处理空分类）。
    geo_ip_used: bool,
    /// 运行期 mmdb 查询需要的数据集；没配 `geo` 时为 None。
    geo: Option<std::sync::Arc<crate::geo::GeoData>>,
    ports: Vec<PortRange>,
    /// 反转本条规则的匹配结果。
    invert: bool,
    destination: Resolved,
}

/// 路由目标的解析结果：静态终端出站，或运行期动态选路的 urltest 组。
#[derive(Clone, Debug)]
enum Resolved {
    /// `reverse` 出站额外携带自身 tag，用于查找已注册的 portal 隧道。
    Static(OutboundKind, Option<Arc<ProxyOutbound>>, Option<Arc<str>>),
    Urltest(Arc<UrltestGroup>),
}

/// `urltest` 组的一个成员及其已解析的出站信息。
#[derive(Clone, Debug)]
pub(crate) struct UrltestMember {
    pub(crate) tag: String,
    kind: OutboundKind,
    proxy: Option<Arc<ProxyOutbound>>,
}

impl UrltestMember {
    /// 探测能否通过这个成员真实拨号。`reject` 与 `reverse` 没有可拨号的
    /// 终端，按 `proxy: None` 当直连会违反它们的语义。
    pub(crate) fn dialable(&self) -> bool {
        matches!(self.kind, OutboundKind::Direct) || self.kind.is_proxy()
    }
}

/// 延迟探测组：周期经各成员拨号 `probe`，选择延迟最低的成员。
///
/// 探测只建立 TCP 连接并立即关闭，不发送业务载荷；UDP 仅复用该选择结果。
#[derive(Debug)]
pub(crate) struct UrltestGroup {
    tag: String,
    members: Vec<UrltestMember>,
    probe: Target,
    interval: Duration,
    tolerance: Duration,
    timeout: Duration,
    current: AtomicUsize,
}

impl UrltestGroup {
    fn new(outbound: &Outbound, members: Vec<UrltestMember>) -> Result<Self> {
        let (host, port) = outbound
            .probe
            .as_deref()
            .and_then(crate::session::parse_endpoint)
            .ok_or_else(|| anyhow!("urltest 组缺少有效 probe"))?;
        Ok(Self {
            tag: outbound.tag.clone(),
            members,
            probe: Target { host, port },
            interval: Duration::from_millis(outbound.interval_ms.unwrap_or(180_000)),
            tolerance: Duration::from_millis(outbound.tolerance_ms.unwrap_or(50)),
            timeout: Duration::from_millis(outbound.probe_timeout_ms.unwrap_or(2_000)),
            current: AtomicUsize::new(0),
        })
    }

    pub(crate) fn tag(&self) -> &str {
        &self.tag
    }

    pub(crate) fn members(&self) -> &[UrltestMember] {
        &self.members
    }

    pub(crate) fn probe_target(&self) -> &Target {
        &self.probe
    }

    pub(crate) fn interval(&self) -> Duration {
        self.interval
    }

    pub(crate) fn tolerance(&self) -> Duration {
        self.tolerance
    }

    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    /// 当前选中的成员下标。
    pub(crate) fn selected_index(&self) -> usize {
        self.current
            .load(Ordering::Relaxed)
            .min(self.members.len().saturating_sub(1))
    }

    pub(crate) fn select(&self) -> (OutboundKind, Option<Arc<ProxyOutbound>>) {
        let member = &self.members[self.selected_index()];
        (member.kind, member.proxy.clone())
    }

    pub(crate) fn update(&self, index: usize) {
        if index < self.members.len() {
            self.current.store(index, Ordering::Relaxed);
        }
    }
}

impl UrltestMember {
    pub(crate) fn proxy(&self) -> Option<&ProxyOutbound> {
        self.proxy.as_deref()
    }
}

/// 已解析的上游代理出站。认证信息只用于握手，`Debug` 输出必须脱敏。
#[derive(Clone)]
pub struct ProxyOutbound {
    pub kind: OutboundKind,
    pub endpoint: Target,
    /// `socks5`/`http` 的用户名与密码。
    pub credentials: Option<(Arc<str>, Arc<str>)>,
    /// `trojan`/`shadowsocks` 的密码。
    pub secret: Option<Arc<str>>,
    /// `vless` 的用户 UUID。
    pub uuid: Option<[u8; 16]>,
    /// `vless` 的 flow；Vision 由出站记录层自行建立。
    pub flow: crate::config::VlessFlow,
    /// `vless` 的 VLESS Encryption 客户端状态。
    pub(crate) encryption: Option<Arc<crate::transport::vless_encryption::ClientPrepared>>,
    /// `shadowsocks` 的加密方法。
    pub method: Option<crate::config::ShadowsocksMethod>,
    /// `shadowsocks` 出站使用 UoT（UDP over TCP）。
    pub udp_over_tcp: bool,
    /// `vmess` 的正文安全类型；缺省由连接层视为 3。
    pub security: Option<u8>,
    /// 已校验的传输参数；HTTP 包装与 UDP 底层承载分别接线。
    pub transport: Option<crate::config::OutboundTransport>,
    pub(crate) kcp: Option<Arc<crate::transport::kcp_client::Client>>,
    pub(crate) quic: Option<Arc<crate::transport::v2ray_quic_client::ClientPrepared>>,
    /// 到上游的 TLS；配置在启动时构建，连接只克隆 `Arc`。
    pub tls: Option<Arc<crate::tls::ClientTls>>,
    /// ShadowTLS v3 客户端；无目标，只能作为其他 TCP 出站的 via detour。
    pub(crate) shadowtls: Option<Arc<crate::transport::shadowtls::ShadowTlsClient>>,
    /// REALITY 客户端；与 `tls` 互斥。
    pub(crate) reality: Option<Arc<crate::tls::reality_client::RealityClient>>,
    /// 链式出站的上一跳；先经它建立到本跳的连接。
    pub via: Option<Arc<ProxyOutbound>>,
    /// `wireguard` 出站的隧道与用户态 TCP 栈。
    pub(crate) wireguard: Option<Arc<crate::transport::wireguard::WireguardOutbound>>,
    /// `hysteria2` 出站的 QUIC 连接与认证状态。
    pub(crate) hysteria2: Option<Arc<crate::transport::hysteria2::ClientPrepared>>,
    /// `tuic` 出站的 QUIC 连接与认证状态。
    pub(crate) tuic: Option<Arc<crate::transport::tuic_client::ClientPrepared>>,
    /// `tuic` 的 UDP 承载方式。
    pub(crate) tuic_udp_mode: crate::config::TuicUdpRelayMode,
    /// Snell记录参数（含脱敏凭据）；逐会话独立salt与nonce。
    pub(crate) snell: Option<Arc<crate::config::SnellClientOptions>>,
    /// TCP顺序连接池；仅显式reuse时构建，活流不强持有池。
    pub(crate) snell_pool: Option<Arc<crate::protocol::snell::client::reuse::Pool>>,
    /// Naive已校验的H2/H3与可选UoT参数，额外头Debug不显示值。
    pub(crate) naive: Option<Arc<crate::config::NaiveClientOptions>>,
    /// AnyTLS每出站共享方案，合法cmd6更新影响后续写与新会话。
    pub(crate) anytls_padding: Option<Arc<crate::transport::anytls_padding::SharedScheme>>,
    /// AnyTLS每出站独立会话池，TCP/UoT共用；不与其他身份混用。
    pub(crate) anytls_pool: Option<Arc<crate::transport::anytls_client::pool::Pool>>,
    /// `nw3-vector` 出站的 Vector 客户端。
    pub(crate) nw3: Option<Arc<nowhere::VectorClient>>,
}

impl PartialEq for ProxyOutbound {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.endpoint == other.endpoint
            && self.credentials == other.credentials
            && self.secret == other.secret
            && self.uuid == other.uuid
            && self.flow == other.flow
            && match (&self.encryption, &other.encryption) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && self.method == other.method
            && self.udp_over_tcp == other.udp_over_tcp
            && self.security == other.security
            && self.transport == other.transport
            && match (&self.kcp, &other.kcp) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.quic, &other.quic) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.tls, &other.tls) {
                (None, None) => true,
                // 同一出站共享同一个 ClientTls；不同出站即使参数相同也不混用。
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.reality, &other.reality) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.shadowtls, &other.shadowtls) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.via, &other.via) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.wireguard, &other.wireguard) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.hysteria2, &other.hysteria2) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.tuic, &other.tuic) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && self.tuic_udp_mode == other.tuic_udp_mode
            && match (&self.snell, &other.snell) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.snell_pool, &other.snell_pool) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.naive, &other.naive) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.anytls_padding, &other.anytls_padding) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.anytls_pool, &other.anytls_pool) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
            && match (&self.nw3, &other.nw3) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
    }
}

impl Eq for ProxyOutbound {}

impl fmt::Debug for ProxyOutbound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyOutbound")
            .field("kind", &self.kind)
            .field("endpoint", &self.endpoint)
            .field("authenticated", &self.credentials.is_some())
            .field("flow", &self.flow)
            .field("encrypted", &self.encryption.is_some())
            .field("tls", &self.tls.is_some())
            .field("shadowtls", &self.shadowtls.is_some())
            .field("reality", &self.reality.is_some())
            .field("kcp", &self.kcp.is_some())
            .field("quic", &self.quic.is_some())
            .field("chained", &self.via.is_some())
            .field("wireguard", &self.wireguard.is_some())
            .field("hysteria2", &self.hysteria2.is_some())
            .field("tuic", &self.tuic.is_some())
            .field("tuic_udp_mode", &self.tuic_udp_mode)
            .field("snell", &self.snell.is_some())
            .field("snell_reuse", &self.snell_pool.is_some())
            .field("naive", &self.naive)
            .field("anytls_pool", &self.anytls_pool.is_some())
            .field("nw3", &self.nw3.is_some())
            .finish()
    }
}

/// 路由选择结果：类型与可选的上游代理。
///
/// 出站组可能在两次选择之间切换成员，因此结果持有 `Arc` 快照而不是借用
/// `Router`。
#[derive(Clone, Debug)]
pub struct Selected {
    pub kind: OutboundKind,
    pub proxy: Option<Arc<ProxyOutbound>>,
    /// `reverse` 出站的 tag；其他出站为 `None`。
    pub(crate) reverse: Option<Arc<str>>,
    /// 是否由规则命中，而非回落到默认出站。
    pub(crate) matched: bool,
}

impl Selected {
    /// UDP 快路径（dokodemo / TUIC / Hysteria2 / Snell / Shadowsocks）只实现
    /// 直连与共享代理中继。`reverse` 是独立上游，`proxy` 为空但绝不是直连；
    /// 在这些路径里必须失败关闭，不能把反向目标当成本地上游发出去。
    pub fn udp_proxied(&self) -> std::io::Result<bool> {
        if self.reverse.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "该 UDP 路径不支持 reverse 出站",
            ));
        }
        Ok(self.proxy.is_some())
    }
}

impl Router {
    pub fn new(config: &Config) -> Result<Self> {
        // 也校验由库调用方直接构造或修改的配置，保证默认出站一定存在。
        config.validate()?;
        let outbounds: HashMap<&str, &Outbound> = config
            .outbounds
            .iter()
            .map(|outbound| (outbound.tag.as_str(), outbound))
            .collect();
        let proxies = proxy_outbounds(config)?;
        let mut groups: HashMap<String, Arc<UrltestGroup>> = HashMap::new();
        let mut resolve = |tag: &str| {
            resolve_outbound(tag, &outbounds, &proxies, &mut groups, &mut HashSet::new())
        };
        // 数据集只加载一次，由所有规则共享（Arc）。
        let geo_data = match config.geo.as_ref() {
            Some(geo) => Some(std::sync::Arc::new(crate::geo::load(geo)?)),
            None => None,
        };
        let mut expansion = crate::geo::ExpansionBudget::default();
        let rules = config
            .route
            .rules
            .iter()
            .enumerate()
            .map(|(rule_index, rule)| {
                let destination = resolve(&rule.outbound)?;
                // `geosite:` / `geoip:` 在此展开成具体项；`mmdb:` 留到运行期。
                let expanded = expand_geo(geo_data.as_deref(), rule, rule_index, &mut expansion)?;
                let domains: Vec<String> = rule
                    .domains
                    .iter()
                    .filter(|value| crate::geo::code_of(value).is_none())
                    .map(|domain| normalize_domain(domain))
                    .collect();
                let domain_suffix: Vec<String> = rule
                    .domain_suffix
                    .iter()
                    .map(|suffix| normalize_domain(suffix))
                    .collect();
                let domain_keyword: Vec<String> = rule
                    .domain_keyword
                    .iter()
                    .map(|keyword| keyword.to_ascii_lowercase())
                    .collect();
                let domain_regex: Vec<regex::Regex> = rule
                    .domain_regex
                    .iter()
                    .map(|pattern| {
                        regex::Regex::new(pattern).map_err(|error| {
                            anyhow::anyhow!("route.rules 的 domain_regex {pattern:?} 无效: {error}")
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                // 展开项的域名与 `domains` 属于同一个 OR 组（都来自配置的
                // `domains` 数组）；正则在这里预编译一次。
                let geo_domains = expanded
                    .domains
                    .iter()
                    .map(CompiledGeoDomain::compile)
                    .collect::<Result<Vec<_>>>()?;
                let mut ip_cidrs: Vec<IpNet> = rule
                    .ip_cidrs
                    .iter()
                    .filter_map(|entry| match entry {
                        crate::config::IpEntry::Cidr(net) => Some(*net),
                        crate::config::IpEntry::Geo(_) => None,
                    })
                    .collect();
                for cidr in expanded.ips {
                    ip_cidrs.push(ipnet_of(cidr)?);
                }
                Ok(CompiledRule {
                    inbounds: rule.inbounds.clone(),
                    networks: rule.networks.clone(),
                    domains,
                    domain_suffix,
                    domain_keyword,
                    domain_regex,
                    ip_cidrs,
                    ip_is_private: rule.ip_is_private,
                    geo_domains,
                    geo_domain_used: expanded.domain_used,
                    mmdb_codes: expanded.mmdb_codes,
                    geo_ip_used: expanded.ip_used,
                    geo: geo_data.clone(),
                    ports: rule.ports.clone(),
                    invert: rule.invert,
                    destination,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let default = resolve(&config.route.default)?;
        let mut urltest_groups: Vec<_> = groups.into_values().collect();
        urltest_groups.sort_by(|left, right| left.tag().cmp(right.tag()));
        // 仅保存匹配条件及已解析的出站类型，不保存入口用户或密码。
        Ok(Self {
            default,
            domain_strategy: config.route.domain_strategy,
            rules,
            urltest_groups,
            proxies,
        })
    }

    /// 按 tag 取得已编译的代理出站；仅用于反向 Bridge 等主动拨号角色。
    pub(crate) fn proxy_by_tag(&self, tag: &str) -> Option<Arc<ProxyOutbound>> {
        self.proxies.get(tag).cloned()
    }

    /// 运行时仍可能保留旧Context快照；热替换必须显式停止其空闲出站池。
    pub(crate) fn close_outbound_pools(&self) {
        for proxy in self.proxies.values() {
            if let Some(pool) = &proxy.snell_pool {
                pool.close();
            }
            if let Some(pool) = &proxy.anytls_pool {
                pool.close();
            }
        }
    }

    pub fn select(&self, inbound: &str, network: Network, target: &Target) -> OutboundKind {
        self.select_outbound(inbound, network, target).kind
    }

    /// 返回完整选择结果；上游代理的出站额外带上握手所需信息。
    pub fn select_outbound(&self, inbound: &str, network: Network, target: &Target) -> Selected {
        self.select_with(inbound, network, target, None)
    }

    /// 解析后 IP 规则使用的选择入口；`resolved` 是域名目标的解析结果。
    pub(crate) fn select_with(
        &self,
        inbound: &str,
        network: Network,
        target: &Target,
        resolved: Option<&[IpAddr]>,
    ) -> Selected {
        let domain = match &target.host {
            Host::Domain(domain) => Some(normalize_domain(domain)),
            Host::Ip(_) => None,
        };
        // 跳过 `NeedIp`：宁可继续看后面的规则，也不在缺证据时做决定。
        match self.rules.iter().find(|rule| {
            rule.evaluate(inbound, network, target, domain.as_deref(), resolved) == RuleMatch::Hit
        }) {
            Some(rule) => resolved_select(&rule.destination, true),
            None => resolved_select(&self.default, false),
        }
    }

    /// 参与本路由器选路的 urltest 组；未引用的组不会探测。
    pub(crate) fn urltest_groups(&self) -> &[Arc<UrltestGroup>] {
        &self.urltest_groups
    }

    /// 该目标是否可能命中带 IP CIDR 的规则。
    ///
    /// 仅检查除 `ip_cidrs` 外的全部条件；用于避免对不可能影响结果的域名
    /// 发起无意义的 DNS 查询。
    pub(crate) fn has_ip_candidates(
        &self,
        inbound: &str,
        network: Network,
        target: &Target,
    ) -> bool {
        let domain = match &target.host {
            Host::Domain(domain) => Some(normalize_domain(domain)),
            Host::Ip(_) => None,
        };
        // 复用同一求值函数：只有真的因为缺地址而无法判定的规则才值得解析。
        self.rules.iter().any(|rule| {
            rule.evaluate(inbound, network, target, domain.as_deref(), None) == RuleMatch::NeedIp
        })
    }

    /// 域名目标的 IP 规则匹配策略。
    pub(crate) fn domain_strategy(&self) -> DomainStrategy {
        self.domain_strategy
    }
}

fn resolved_select(destination: &Resolved, matched: bool) -> Selected {
    match destination {
        Resolved::Static(kind, proxy, reverse) => Selected {
            kind: *kind,
            proxy: proxy.clone(),
            reverse: reverse.clone(),
            matched,
        },
        Resolved::Urltest(group) => {
            let (kind, proxy) = group.select();
            Selected {
                kind,
                proxy,
                reverse: None,
                matched,
            }
        }
    }
}

/// 把 `selector`/`urltest` 组解析到实际选择来源；终端出站直接返回自身。
///
/// `visiting` 只记录当前递归路径，共享成员不会误判为循环。
fn resolve_outbound(
    tag: &str,
    outbounds: &HashMap<&str, &Outbound>,
    proxies: &HashMap<String, Arc<ProxyOutbound>>,
    groups: &mut HashMap<String, Arc<UrltestGroup>>,
    visiting: &mut HashSet<String>,
) -> Result<Resolved> {
    if let Some(group) = groups.get(tag) {
        return Ok(Resolved::Urltest(group.clone()));
    }
    let outbound = outbounds
        .get(tag)
        .copied()
        .ok_or_else(|| anyhow!("路由引用了不存在的出站"))?;
    match outbound.kind {
        OutboundKind::Selector => {
            if !visiting.insert(tag.to_owned()) {
                return Err(anyhow!("outbounds 的 selector/urltest 存在循环引用"));
            }
            let member = outbound
                .default
                .as_deref()
                .or_else(|| outbound.outbounds.first().map(String::as_str))
                .ok_or_else(|| anyhow!("selector 组没有成员"))?;
            let resolved = resolve_outbound(member, outbounds, proxies, groups, visiting);
            visiting.remove(tag);
            resolved
        }
        OutboundKind::Urltest => {
            if !visiting.insert(tag.to_owned()) {
                return Err(anyhow!("outbounds 的 selector/urltest 存在循环引用"));
            }
            let mut members = Vec::with_capacity(outbound.outbounds.len());
            for member in &outbound.outbounds {
                match resolve_outbound(member, outbounds, proxies, groups, visiting)? {
                    Resolved::Static(kind, proxy, _) => {
                        let tag = outbounds[member.as_str()].tag.clone();
                        members.push(UrltestMember { tag, kind, proxy });
                    }
                    // 嵌套 urltest 已在配置校验阶段拒绝；直接构造的配置这里也
                    // 失败关闭，避免探测与选路语义变成两跳。
                    Resolved::Urltest(_) => {
                        return Err(anyhow!("urltest 组的成员不得再是 urltest"));
                    }
                }
            }
            let group = Arc::new(UrltestGroup::new(outbound, members)?);
            visiting.remove(tag);
            groups.insert(tag.to_owned(), group.clone());
            Ok(Resolved::Urltest(group))
        }
        _ => Ok(Resolved::Static(
            outbound.kind,
            proxies.get(tag).cloned(),
            (outbound.kind == OutboundKind::Reverse)
                .then(|| Arc::<str>::from(outbound.tag.as_str())),
        )),
    }
}

/// 启动前检查所有出站的可加载性，包括未参与路由的 TLS 信任锚。
pub fn check_outbounds(config: &Config) -> Result<()> {
    proxy_outbounds(config).map(|_| ())
}

/// 构建所有上游代理出站及其 `via` 链。
///
/// 循环引用与非法引用已由 `Config::validate` 拒绝；这里仍用 `visiting`
/// 防御直接构造的配置，避免递归无界。
fn proxy_outbounds(config: &Config) -> Result<HashMap<String, Arc<ProxyOutbound>>> {
    let by_tag: HashMap<&str, &Outbound> = config
        .outbounds
        .iter()
        .map(|outbound| (outbound.tag.as_str(), outbound))
        .collect();
    let mut cache = HashMap::new();
    for outbound in &config.outbounds {
        if outbound.kind.is_proxy() {
            build_proxy(
                outbound.tag.as_str(),
                &by_tag,
                &mut cache,
                &mut HashSet::new(),
            )?;
        }
    }
    Ok(cache)
}

fn build_proxy(
    tag: &str,
    by_tag: &HashMap<&str, &Outbound>,
    cache: &mut HashMap<String, Arc<ProxyOutbound>>,
    visiting: &mut HashSet<String>,
) -> Result<Arc<ProxyOutbound>> {
    if let Some(proxy) = cache.get(tag) {
        return Ok(proxy.clone());
    }
    ensure!(visiting.insert(tag.to_owned()), "出站 via 存在循环引用");
    let outbound = by_tag
        .get(tag)
        .copied()
        .ok_or_else(|| anyhow!("引用了不存在的出站"))?;
    let via = match &outbound.via {
        Some(via) => Some(build_proxy(via, by_tag, cache, visiting)?),
        None => None,
    };
    let proxy = proxy_from_outbound(outbound, via)?;
    visiting.remove(tag);
    cache.insert(tag.to_owned(), proxy.clone());
    Ok(proxy)
}

fn proxy_from_outbound(
    outbound: &Outbound,
    via: Option<Arc<ProxyOutbound>>,
) -> Result<Arc<ProxyOutbound>> {
    let (host, port) = if outbound.kind == OutboundKind::Nw3Vector {
        // NW3 Vector 的唯一端点是 `vector://` URL；endpoint 只是可选展示字段。
        let raw = outbound
            .url
            .as_deref()
            .ok_or_else(|| anyhow!("出站 {} 缺少 url", outbound.tag))?;
        let parsed =
            url::Url::parse(raw).map_err(|_| anyhow!("出站 {} 的 url 无效", outbound.tag))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("出站 {} 的 url 缺少主机", outbound.tag))?;
        let host = match host.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(host.to_owned()),
        };
        // Nowhere 的显式载波语法把端口放在 /tcp:PORT 或 /udp:PORT；
        // URL authority 没有端口并不代表端点缺失。
        let port = parsed
            .port()
            .or_else(|| {
                let mut parts = parsed.path().trim_start_matches('/').split(':');
                let carrier = parts.next()?;
                if !matches!(carrier, "tcp" | "tcp4" | "tcp6" | "udp" | "udp4" | "udp6") {
                    return None;
                }
                parts.next()?.parse::<u16>().ok().filter(|port| *port != 0)
            })
            .ok_or_else(|| anyhow!("出站 {} 的 url 缺少有效载波端口", outbound.tag))?;
        (host, port)
    } else {
        let endpoint = outbound
            .endpoint
            .as_deref()
            .ok_or_else(|| anyhow!("出站 {} 缺少 endpoint", outbound.tag))?;
        crate::session::parse_endpoint(endpoint)
            .ok_or_else(|| anyhow!("出站 {} 的 endpoint 无效", outbound.tag))?
    };
    let credentials = match (&outbound.username, &outbound.password) {
        (Some(username), Some(password)) => Some((
            Arc::<str>::from(username.as_str()),
            Arc::<str>::from(password.as_str()),
        )),
        _ => None,
    };
    let secret = match outbound.kind {
        OutboundKind::Trojan | OutboundKind::Shadowsocks | OutboundKind::Anytls => {
            outbound.password.as_deref().map(Arc::<str>::from)
        }
        _ => None,
    };
    let uuid = match (&outbound.kind, &outbound.uuid) {
        (OutboundKind::Vless | OutboundKind::Vmess, Some(uuid)) => crate::config::parse_uuid(uuid),
        _ => None,
    };
    let encryption = match (&outbound.kind, &outbound.encryption) {
        (OutboundKind::Vless, Some(value)) => {
            let parsed = crate::config::vless_encryption::parse_client(value)
                .map_err(|error| {
                    anyhow!(
                        "出站 {} 的 vless encryption 配置无效: {error}",
                        outbound.tag
                    )
                })?
                .ok_or_else(|| anyhow!("出站 {} 的 vless encryption 不得为空", outbound.tag))?;
            Some(Arc::new(
                crate::transport::vless_encryption::ClientPrepared::new(&parsed).map_err(
                    |error| {
                        anyhow!(
                            "出站 {} 的 vless encryption 初始化失败: {error}",
                            outbound.tag
                        )
                    },
                )?,
            ))
        }
        _ => None,
    };
    let method = match outbound.kind {
        OutboundKind::Shadowsocks => outbound.method,
        _ => None,
    };
    let security = match outbound.kind {
        OutboundKind::Vmess => outbound.security,
        _ => None,
    };
    let transport = match outbound.kind {
        OutboundKind::Vless | OutboundKind::Vmess | OutboundKind::Trojan => {
            outbound.transport.clone()
        }
        _ => None,
    };
    let wireguard = match outbound.kind {
        OutboundKind::Wireguard => {
            let options = outbound
                .wireguard
                .as_ref()
                .ok_or_else(|| anyhow!("出站 {} 缺少 wireguard 配置", outbound.tag))?;
            let config = crate::transport::wireguard::WireguardConfig::parse(options)
                .map_err(|error| anyhow!("出站 {} 的 wireguard 配置无效: {error}", outbound.tag))?;
            Some(Arc::new(
                crate::transport::wireguard::WireguardOutbound::new(
                    config,
                    Target {
                        host: host.clone(),
                        port,
                    },
                ),
            ))
        }
        _ => None,
    };
    let tls = match &outbound.tls {
        None => None,
        Some(tls) => {
            let name = match &tls.server_name {
                Some(name) => name.clone(),
                None => match &host {
                    Host::Ip(ip) => ip.to_string(),
                    Host::Domain(domain) => domain.clone(),
                },
            };
            // ShadowTLS v3 的 HMAC 证明只能走 TLS 1.3；TLS 1.2 回落必须失败关闭。
            let client = if outbound.kind == OutboundKind::ShadowTls
                || (outbound.kind == OutboundKind::Vless
                    && outbound.flow == Some(crate::config::VlessFlow::Vision))
            {
                crate::tls::client_vision(std::path::Path::new(&tls.ca_file), &name)
            } else {
                crate::tls::client(std::path::Path::new(&tls.ca_file), &name)
            }
            .map_err(|error| anyhow!("出站 {} 的 TLS 配置无效: {error}", outbound.tag))?;
            Some(Arc::new(client))
        }
    };
    let shadowtls = match outbound.kind {
        OutboundKind::ShadowTls => {
            let password = outbound
                .password
                .as_deref()
                .ok_or_else(|| anyhow!("出站 {} 缺少 password", outbound.tag))?;
            let tls = tls
                .clone()
                .ok_or_else(|| anyhow!("出站 {} 缺少 TLS 配置", outbound.tag))?;
            Some(
                crate::transport::shadowtls::ShadowTlsClient::new(password, tls).map_err(
                    |error| {
                        anyhow!(
                            "出站 {} 的 ShadowTLS 客户端初始化失败: {error}",
                            outbound.tag
                        )
                    },
                )?,
            )
        }
        _ => None,
    };
    let kcp = match transport.as_ref() {
        Some(transport) if transport.kind == crate::config::OutboundTransportType::Kcp => {
            let prepared =
                crate::transport::kcp::prepare(&transport.kcp.clone().unwrap_or_default())
                    .map_err(|_| anyhow!("出站 {} 的 mKCP 参数无效", outbound.tag))?;
            Some(Arc::new(crate::transport::kcp_client::Client::new(
                prepared,
            )))
        }
        _ => None,
    };
    let quic = match transport.as_ref() {
        Some(transport)
            if transport.kind == crate::config::OutboundTransportType::Quic
                || transport.kind == crate::config::OutboundTransportType::Xhttp
                    && transport.http_version() == crate::config::OutboundHttpVersion::Http3 =>
        {
            let client = tls.as_ref().ok_or_else(|| anyhow!("QUIC 出站缺少 TLS"))?;
            let name = outbound
                .tls
                .as_ref()
                .and_then(|tls| tls.server_name.clone())
                .unwrap_or_else(|| match &host {
                    Host::Ip(ip) => ip.to_string(),
                    Host::Domain(domain) => domain.clone(),
                });
            Some(Arc::new(
                crate::transport::v2ray_quic_client::ClientPrepared::with_quic(
                    client.config.clone(),
                    name,
                    &transport.quic.clone().unwrap_or_default(),
                ),
            ))
        }
        _ => None,
    };
    let reality = match &outbound.reality {
        Some(options) => Some(
            crate::tls::reality_client::RealityClient::from_config(options)
                .map_err(|error| anyhow!("出站 {} 的 REALITY 配置无效: {error}", outbound.tag))?,
        ),
        None => None,
    };
    let nw3 = match outbound.kind {
        OutboundKind::Nw3Vector => {
            let raw = outbound
                .url
                .as_deref()
                .ok_or_else(|| anyhow!("出站 {} 缺少 url", outbound.tag))?;
            let parsed = url::Url::parse(raw)
                .map_err(|error| anyhow!("出站 {} 的 url 无效: {error}", outbound.tag))?;
            Some(Arc::new(
                nowhere::VectorClient::new(parsed, nowhere::Logger).map_err(|error| {
                    anyhow!("出站 {} 的 Vector 配置无效: {error}", outbound.tag)
                })?,
            ))
        }
        _ => None,
    };
    let tuic = match outbound.kind {
        OutboundKind::Tuic => {
            let ca_file = outbound
                .tls
                .as_ref()
                .map(|tls| tls.ca_file.as_str())
                .ok_or_else(|| anyhow!("出站 {} 缺少 TLS 配置", outbound.tag))?;
            let tls = crate::tls::client_config(std::path::Path::new(ca_file))
                .map_err(|error| anyhow!("出站 {} 的 TLS 配置无效: {error}", outbound.tag))?;
            let server_name = outbound
                .tls
                .as_ref()
                .and_then(|tls| tls.server_name.clone())
                .unwrap_or_else(|| match &host {
                    Host::Ip(ip) => ip.to_string(),
                    Host::Domain(domain) => domain.clone(),
                });
            let uuid = outbound
                .uuid
                .as_deref()
                .and_then(crate::config::parse_uuid)
                .ok_or_else(|| anyhow!("出站 {} 的 uuid 无效", outbound.tag))?;
            let password = outbound
                .password
                .clone()
                .ok_or_else(|| anyhow!("出站 {} 缺少 password", outbound.tag))?;
            Some(Arc::new(
                crate::transport::tuic_client::ClientPrepared::new(
                    Target {
                        host: host.clone(),
                        port,
                    },
                    tls,
                    server_name,
                    uuid,
                    password,
                    outbound.tuic.clone().unwrap_or_default(),
                )
                .map_err(|error| anyhow!("出站 {} 的TUIC策略无效: {error}", outbound.tag))?,
            ))
        }
        _ => None,
    };
    let hysteria2 = match outbound.kind {
        OutboundKind::Hysteria2 => {
            let ca_file = outbound
                .tls
                .as_ref()
                .map(|tls| tls.ca_file.as_str())
                .ok_or_else(|| anyhow!("出站 {} 缺少 TLS 配置", outbound.tag))?;
            let tls = crate::tls::client_config_with_alpn(std::path::Path::new(ca_file), &[b"h3"])
                .map_err(|error| anyhow!("出站 {} 的 TLS 配置无效: {error}", outbound.tag))?;
            let server_name = outbound
                .tls
                .as_ref()
                .and_then(|tls| tls.server_name.clone())
                .unwrap_or_else(|| match &host {
                    Host::Ip(ip) => ip.to_string(),
                    Host::Domain(domain) => domain.clone(),
                });
            let password = outbound
                .password
                .clone()
                .ok_or_else(|| anyhow!("出站 {} 缺少 password", outbound.tag))?;
            let obfs = crate::transport::hysteria2::client_obfs(
                outbound
                    .hysteria2
                    .as_ref()
                    .and_then(|options| options.obfs.as_ref()),
            )
            .map_err(|error| anyhow!("出站 {} 的 hysteria2 obfs 无效: {error}", outbound.tag))?;
            let bandwidth = crate::transport::hysteria2::Bandwidth::from_mbps(
                outbound
                    .hysteria2
                    .as_ref()
                    .and_then(|options| options.up_mbps),
                outbound
                    .hysteria2
                    .as_ref()
                    .and_then(|options| options.down_mbps),
            )
            .map_err(|error| {
                anyhow!("出站 {} 的 hysteria2 bandwidth 无效: {error}", outbound.tag)
            })?;
            Some(Arc::new(crate::transport::hysteria2::ClientPrepared::new(
                Target {
                    host: host.clone(),
                    port,
                },
                tls,
                server_name,
                password,
                obfs,
                bandwidth,
            )))
        }
        _ => None,
    };
    let anytls_padding = (outbound.kind == OutboundKind::Anytls)
        .then(|| Arc::new(crate::transport::anytls_padding::SharedScheme::default()));
    let anytls_pool = anytls_padding.as_ref().map(|scheme| {
        Arc::new(crate::transport::anytls_client::pool::Pool::new(
            outbound.anytls.clone().unwrap_or_default(),
            scheme.clone(),
        ))
    });
    Ok(Arc::new(ProxyOutbound {
        kind: outbound.kind,
        endpoint: Target { host, port },
        credentials,
        secret,
        uuid,
        flow: outbound.flow.unwrap_or_default(),
        encryption,
        method,
        udp_over_tcp: outbound.udp_over_tcp && outbound.kind == OutboundKind::Shadowsocks,
        security,
        transport,
        kcp,
        quic,
        tls,
        shadowtls,
        reality,
        via,
        wireguard,
        hysteria2,
        tuic,
        tuic_udp_mode: outbound
            .tuic
            .as_ref()
            .map_or(crate::config::TuicUdpRelayMode::Native, |options| {
                options.udp_relay_mode
            }),
        snell: outbound.snell.clone().map(Arc::new),
        snell_pool: outbound
            .snell
            .as_ref()
            .filter(|options| options.reuse)
            .map(|_| Arc::new(crate::protocol::snell::client::reuse::Pool::default())),
        naive: outbound.naive.clone().map(Arc::new),
        anytls_padding,
        anytls_pool,
        nw3,
    }))
}

/// 去掉内部 relay 前缀，还原为配置里可见的入口 tag。
///
/// NW3 的 `out=direct` 经内部 SOCKS5 进入控制面，那条连接的 `inbound`
/// 是 `__nw3_relay:<原 tag>`。规则里写的是原 tag，因此匹配前先归一化；
/// 否则 `inbounds: ["nw3-in"]` 对 NW3 流量永远不成立。
fn inbound_tag(inbound: &str) -> &str {
    inbound
        .strip_prefix(crate::runtime::NW3_RELAY_PREFIX)
        .unwrap_or(inbound)
}

impl CompiledRule {
    fn evaluate(
        &self,
        inbound: &str,
        network: Network,
        target: &Target,
        domain: Option<&str>,
        resolved: Option<&[IpAddr]>,
    ) -> RuleMatch {
        // 基础条件不成立时，**取反仍然要生效**：端口不符已经足以确定
        // 「这条规则不匹配」，取反后就应当是命中，且不需要地址证据。
        let result = if self.matches_base(inbound, network, target, domain) {
            match self.ip_outcome(target, resolved) {
                IpOutcome::Always => RuleMatch::Hit,
                IpOutcome::Never => RuleMatch::Miss,
                IpOutcome::NeedIp => RuleMatch::NeedIp,
                IpOutcome::Value(true) => RuleMatch::Hit,
                IpOutcome::Value(false) => RuleMatch::Miss,
            }
        } else {
            RuleMatch::Miss
        };
        // invert 只翻转本条规则，不影响其它规则；未知保持未知。
        if self.invert { result.negate() } else { result }
    }

    /// 判定 IP 维度。
    ///
    /// 设计要点：
    /// - **同一个候选 IP** 必须同时满足 `ip_is_private` 与 CIDR/mmdb 组，
    ///   不能两个条件各自由不同地址满足（否则「命中」没有可指认的依据）。
    /// - 域名未解析时返回 `NeedIp`，交由调用方决定是否解析；
    ///   它不会在 `invert` 下变成命中。
    fn ip_outcome(&self, target: &Target, resolved: Option<&[IpAddr]>) -> IpOutcome {
        let has_group = !self.ip_cidrs.is_empty() || !self.mmdb_codes.is_empty();
        if !self.ip_is_private && !has_group {
            // 完全没有 IP 条件；但如果引用过地理集合且展开为空，
            // 那是「有条件且永远不成立」，不能当成「没有条件」。
            return if self.geo_ip_used {
                IpOutcome::Never
            } else {
                IpOutcome::Always
            };
        }
        if self.geo_ip_used && !has_group {
            return IpOutcome::Never;
        }
        let hit = |ip: IpAddr| {
            (!self.ip_is_private || is_private_ip(&ip))
                && (!has_group
                    || self.ip_cidrs.iter().any(|cidr| cidr.contains(&ip))
                    || self.mmdb_hit(ip))
        };
        match &target.host {
            Host::Ip(ip) => IpOutcome::Value(hit(*ip)),
            Host::Domain(_) => match resolved {
                // 空解析结果视为「仍未知」：DNS 没给出地址不等于
                // 「已证明不属于该集合」，不能被 invert 翻成命中。
                Some(addresses) if !addresses.is_empty() => {
                    IpOutcome::Value(addresses.iter().any(|ip| hit(*ip)))
                }
                _ => IpOutcome::NeedIp,
            },
        }
    }

    fn mmdb_hit(&self, ip: IpAddr) -> bool {
        let Some(geo) = self.geo.as_deref() else {
            return false;
        };
        self.mmdb_codes
            .iter()
            .any(|code| geo.mmdb_matches(code, ip) == Some(true))
    }

    /// 除 `ip_cidrs` 外的全部条件。
    fn matches_base(
        &self,
        inbound: &str,
        network: Network,
        target: &Target,
        domain: Option<&str>,
    ) -> bool {
        // 空字段不限制；不同字段取交集，同字段的多个值取并集。
        (self.inbounds.is_empty()
            || self.inbounds.iter().any(|tag| tag == inbound_tag(inbound)))
            && (self.networks.is_empty() || self.networks.contains(&network))
            // `domains` 与地理展开项是同一个 OR 组：两者都来自配置的
            // `domains` 数组，而 Xray 的 domain 数组内部是并集。
            && if self.domains.is_empty() && self.geo_domains.is_empty() {
                // 配了 geo 却展开为空（例如空分类）时，必须视为「永不匹配」，
                // 不能退化成「没有条件」。
                !self.geo_domain_used
            } else {
                domain.is_some_and(|domain| {
                    self.domains.iter().any(|item| item == domain)
                        || self.geo_domains.iter().any(|item| item.matches(domain))
                })
            }
            && (self.domain_suffix.is_empty()
                || domain.is_some_and(|domain| {
                    self.domain_suffix
                        .iter()
                        .any(|suffix| matches_domain_suffix(domain, suffix))
                }))
            && (self.domain_keyword.is_empty()
                || domain.is_some_and(|domain| {
                    self.domain_keyword
                        .iter()
                        .any(|keyword| domain.contains(keyword.as_str()))
                }))
            && (self.domain_regex.is_empty()
                || domain.is_some_and(|domain| {
                    self.domain_regex
                        .iter()
                        .any(|pattern| pattern.is_match(domain))
                }))
            && (self.ports.is_empty()
                || self
                    .ports
                    .iter()
                    .any(|range| (range.start..=range.end).contains(&target.port)))
    }
}

/// 非公网地址，与 sing-box v1.14.4 的 `!N.IsPublicAddr` 逐条对齐，其定义是：
/// `IsPrivate || IsLoopback || IsMulticast || IsLinkLocalUnicast ||
/// IsInterfaceLocalMulticast || IsUnspecified`。
///
/// 因此**不包含** CGNAT 100.64.0.0/10（Go `netip.IsPrivate` 只认 RFC1918 与
/// fc00::/7），也不包含 IPv4 广播地址。不要凭直觉扩充这个集合。
pub(crate) fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_multicast() || v6.is_unspecified()
                // fc00::/7：Go IsPrivate 的 IPv6 部分
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10：Go IsLinkLocalUnicast
                || (v6.segments()[0] & 0xffc0) == 0xfe80
            // ff01::/16：Go IsInterfaceLocalMulticast（被 is_multicast 覆盖）
        }
    }
}

pub(crate) fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

/// 域名后缀匹配：`example.com` 与 `.example.com` 都匹配自身及子域名，
/// 但不会把 `badexample.com` 误判为后缀命中。
pub(crate) fn matches_domain_suffix(domain: &str, suffix: &str) -> bool {
    let core = suffix.trim_start_matches('.');
    !core.is_empty()
        && (domain == core
            || domain
                .strip_suffix(core)
                .is_some_and(|prefix| prefix.ends_with('.')))
}

#[cfg(test)]
mod invert_ip_tests {
    use super::*;

    fn router(rules: serde_json::Value) -> Router {
        let value = serde_json::json!({
            "version": 1,
            "inbounds": [{"type": "socks5", "tag": "s", "listen": "127.0.0.1:0"}],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "reject", "tag": "reject"},
                {"type": "direct", "tag": "proxy"}
            ],
            "route": {"default": "direct", "rules": rules}
        });
        let config = crate::config::Config::from_json(&value.to_string()).unwrap();
        Router::new(&config).unwrap()
    }

    fn domain(name: &str) -> Target {
        Target {
            host: Host::Domain(name.to_owned()),
            port: 443,
        }
    }

    /// 反向 IP 规则在域名未解析时不得命中；解析到集合内则仍不命中，
    /// 解析到集合外才命中。
    #[test]
    fn inverted_ip_rule_waits_for_address() {
        let router = router(serde_json::json!([
            {"ip_cidrs": ["10.0.0.0/8"], "invert": true, "outbound": "reject"}
        ]));
        let target = domain("a.test");
        // 首轮（未解析）：跳过，回落默认。
        assert_eq!(
            router.select_outbound("s", Network::Tcp, &target).kind,
            OutboundKind::Direct
        );
        // 解析到集合内 → 反向规则不命中。
        let inside = ["10.1.2.3".parse::<IpAddr>().unwrap()];
        assert_eq!(
            router
                .select_with("s", Network::Tcp, &target, Some(&inside))
                .kind,
            OutboundKind::Direct
        );
        // 解析到集合外 → 命中。
        let outside = ["192.0.2.1".parse::<IpAddr>().unwrap()];
        assert_eq!(
            router
                .select_with("s", Network::Tcp, &target, Some(&outside))
                .kind,
            OutboundKind::Reject
        );
    }

    /// 反向 IP 规则不能遮蔽后面的明确域名规则。
    #[test]
    fn deferred_ip_does_not_shadow_domain_rule() {
        let router = router(serde_json::json!([
            {"ip_cidrs": ["10.0.0.0/8"], "invert": true, "outbound": "reject"},
            {"domains": ["a.test"], "outbound": "reject"}
        ]));
        let target = domain("a.test");
        assert_eq!(
            router.select_outbound("s", Network::Tcp, &target).kind,
            OutboundKind::Reject
        );
        // 第二条是明确域名规则命中；`matched` 为真意味着不会再解析。
        assert!(router.select_outbound("s", Network::Tcp, &target).matched);
    }

    /// 端口已不符时取反已确定为真，不需要解析。
    #[test]
    fn inverted_base_miss_is_decisive() {
        let router = router(serde_json::json!([
            {"ports": [{"start": 443, "end": 443}], "ip_cidrs": ["10.0.0.0/8"],
             "invert": true, "outbound": "reject"}
        ]));
        let target = Target {
            host: Host::Domain("a.test".into()),
            port: 80,
        };
        // base（端口）不成立 → 取反后直接命中，无需地址。
        assert_eq!(
            router.select_outbound("s", Network::Tcp, &target).kind,
            OutboundKind::Reject
        );
        assert!(!router.has_ip_candidates("s", Network::Tcp, &target));
    }

    /// 「尚不知道」不能当成「不属于集合」。
    #[test]
    fn unknown_is_not_non_member() {
        let router = router(serde_json::json!([
            {"ip_cidrs": ["10.0.0.0/8"], "invert": true, "outbound": "reject"}
        ]));
        let target = domain("a.test");
        // as-is：不解析，直接回落默认。
        assert_eq!(
            router.select_outbound("s", Network::Tcp, &target).kind,
            OutboundKind::Direct
        );
        // 空解析结果同样视为未知。
        assert_eq!(
            router
                .select_with("s", Network::Tcp, &target, Some(&[]))
                .kind,
            OutboundKind::Direct
        );
    }

    /// 同一候选地址必须同时满足私网与 CIDR，不能各自由不同地址满足。
    #[test]
    fn resolved_ip_conditions_require_same_address() {
        let mismatched = router(serde_json::json!([
            {"ip_is_private": true, "ip_cidrs": ["192.0.2.0/24"], "outbound": "reject"}
        ]));
        let target = domain("a.test");
        let private = "127.0.0.1".parse::<IpAddr>().unwrap();
        let in_cidr = "192.0.2.5".parse::<IpAddr>().unwrap();
        // 两个地址分别满足一个条件 → 不命中。
        assert_eq!(
            mismatched
                .select_with("s", Network::Tcp, &target, Some(&[private, in_cidr]))
                .kind,
            OutboundKind::Direct
        );
        // 单个地址同时满足 → 命中。
        assert_eq!(
            mismatched
                .select_with("s", Network::Tcp, &target, Some(&[private]))
                .kind,
            OutboundKind::Direct,
            "私网但不落在 CIDR 内"
        );
        let matched = router(serde_json::json!([
            {"ip_is_private": true, "ip_cidrs": ["127.0.0.0/8"], "outbound": "reject"}
        ]));
        let both = "127.0.0.1".parse::<IpAddr>().unwrap();
        assert_eq!(
            matched
                .select_with("s", Network::Tcp, &target, Some(&[both]))
                .kind,
            OutboundKind::Reject
        );
    }
}

#[cfg(test)]
mod geo_expand_tests {
    use super::*;

    /// 真实数据经过 Router 编译后，`google.com` 必须真的选中 reject 出站。
    ///
    /// 这条比「展开结果里有 Suffix」更强：它验证展开结果真的进了编译后的
    /// 规则，并参与了选择。
    #[test]
    fn real_geosite_router_selects_reject_for_google() {
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test-artifacts/geodata");
        if !dir.join("geosite.dat").is_file() {
            eprintln!("跳过：未下载真实数据集");
            return;
        }
        let value = serde_json::json!({
            "version": 1,
            "geo": {"geosite": dir.join("geosite.dat")},
            "inbounds": [{"type": "socks5", "tag": "s", "listen": "127.0.0.1:0"}],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "reject", "tag": "reject"}
            ],
            "route": {
                "default": "direct",
                "rules": [{"domains": ["geosite:google"], "outbound": "reject"}]
            }
        });
        let config = crate::config::Config::from_json(&value.to_string()).unwrap();
        eprintln!("config.geo.is_some() = {}", config.geo.is_some());
        let router = Router::new(&config).unwrap();
        eprintln!("编译后规则数 = {}", router.rules.len());
        if let Some(rule) = router.rules.first() {
            eprintln!(
                "rule0: domains={} suffix={} keyword={} regex={} inbounds={:?} networks={:?}",
                rule.domains.len(),
                rule.domain_suffix.len(),
                rule.domain_keyword.len(),
                rule.domain_regex.len(),
                rule.inbounds,
                rule.networks
            );
            eprintln!(
                "rule0 含 google.com 后缀: {}",
                rule.domain_suffix.iter().any(|s| s == "google.com")
            );
            eprintln!("rule0 destination kind = {:?}", rule.destination);
        }
        let target = Target {
            host: Host::Domain("google.com".into()),
            port: 443,
        };
        let selected = router.select_outbound("s", Network::Tcp, &target);
        assert_eq!(
            selected.kind,
            OutboundKind::Reject,
            "google.com 应命中 geosite:google 规则"
        );
    }

    /// 空分类必须「永不匹配」，不能退化成「没有条件」。
    #[test]
    fn empty_geo_category_never_matches() {
        let dir = tempfile::tempdir().unwrap();
        // 手写一个含空分类的 GeoSiteList：只写 code，不写 domain。
        let mut site = Vec::new();
        site.extend_from_slice(&[0x0a, 0x05]); // field 1 (code), len 5
        site.extend_from_slice(b"empty");
        let mut list = Vec::new();
        list.extend_from_slice(&[0x0a, site.len() as u8]); // field 1 (entry)
        list.extend_from_slice(&site);
        let path = dir.path().join("geosite.dat");
        std::fs::write(&path, &list).unwrap();

        let value = serde_json::json!({
            "version": 1,
            "geo": {"geosite": path},
            "inbounds": [{"type": "socks5", "tag": "s", "listen": "127.0.0.1:0"}],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "reject", "tag": "reject"}
            ],
            "route": {
                "default": "direct",
                "rules": [{"domains": ["geosite:empty"], "outbound": "reject"}]
            }
        });
        let config = crate::config::Config::from_json(&value.to_string()).unwrap();
        let router = Router::new(&config).unwrap();
        for host in [
            Host::Domain("anything.test".into()),
            Host::Ip("127.0.0.1".parse().unwrap()),
        ] {
            let target = Target { host, port: 443 };
            let selected = router.select_outbound("s", Network::Tcp, &target);
            assert_eq!(
                selected.kind,
                OutboundKind::Direct,
                "空分类不应匹配任何目标"
            );
        }
    }

    /// 真实数据展开后，规则里必须真的出现 `google.com` 的后缀项。
    #[test]
    fn real_geosite_expands_into_rule() {
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".test-artifacts/geodata");
        if !dir.join("geosite.dat").is_file() {
            eprintln!("跳过：未下载真实数据集");
            return;
        }
        let geo = crate::config::GeoConfig {
            geosite: Some(dir.join("geosite.dat")),
            ..Default::default()
        };
        let data = crate::geo::load(&geo).unwrap();
        let rule: Rule = serde_json::from_value(serde_json::json!({
            "domains": ["geosite:google"],
            "outbound": "direct"
        }))
        .unwrap();
        let expanded = expand_geo(
            Some(&data),
            &rule,
            0,
            &mut crate::geo::ExpansionBudget::default(),
        )
        .unwrap();
        let suffix = expanded
            .domains
            .iter()
            .filter(
                |item| matches!(item, crate::geo::DomainMatcher::Suffix(v) if v == "google.com"),
            )
            .count();
        assert!(suffix > 0, "google.com 应作为后缀项出现在展开结果里");
        assert!(expanded.domain_used);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use serde_json::{Value, json};

    fn config_with(rules: Value, default: &str) -> Config {
        Config::from_json(&json!({
            "version": 1,
            "inbounds": [
                {"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"},
                {"type": "socks5", "tag": "other", "listen": "[::1]:0"}
            ],
            "outbounds": [{"tag": "allow", "type": "direct"}, {"tag": "deny", "type": "reject"}],
            "route": {"default": default, "rules": rules}
        }).to_string()).unwrap()
    }

    fn domain(name: &str, port: u16) -> Target {
        Target {
            host: Host::Domain(name.to_owned()),
            port,
        }
    }

    fn ip(address: &str, port: u16) -> Target {
        Target {
            host: Host::Ip(address.parse().unwrap()),
            port,
        }
    }

    #[test]
    fn tunnel_outbounds_resolve_to_their_proxy_kind() {
        let key = base64::engine::general_purpose::STANDARD.encode([3u8; 32]);
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
                "outbounds": [
                    {"type": "direct", "tag": "direct"},
                    {"type": "wireguard", "tag": "wg", "endpoint": "127.0.0.1:51820",
                     "wireguard": {"private_key": key, "peer_public_key": key,
                                   "address": ["10.66.0.2/32"]}}
                ],
                "route": {"default": "direct", "rules": [
                    {"ports": [{"start": 1, "end": 1}], "outbound": "wg"}
                ]}
            })
            .to_string(),
        )
        .unwrap();
        let router = Router::new(&config).unwrap();
        let wireguard = router.select_outbound("socks", Network::Tcp, &ip("10.0.0.1", 1));
        assert_eq!(wireguard.kind, OutboundKind::Wireguard);
        assert!(
            wireguard
                .proxy
                .as_ref()
                .is_some_and(|proxy| proxy.wireguard.is_some())
        );
    }

    #[test]
    fn explicit_default_and_first_match_define_precedence() {
        let cases = [
            (json!([]), "allow", OutboundKind::Direct),
            (json!([]), "deny", OutboundKind::Reject),
            (
                json!([{"outbound": "deny"}, {"outbound": "allow"}]),
                "allow",
                OutboundKind::Reject,
            ),
            (
                json!([{"outbound": "allow"}, {"outbound": "deny"}]),
                "deny",
                OutboundKind::Direct,
            ),
            (
                json!([
                    {"ports": [{"start": 443, "end": 443}], "outbound": "deny"},
                    {"outbound": "allow"}
                ]),
                "allow",
                OutboundKind::Reject,
            ),
            (
                json!([
                    {"ports": [{"start": 80, "end": 80}], "outbound": "deny"},
                    {"outbound": "allow"}
                ]),
                "deny",
                OutboundKind::Direct,
            ),
        ];
        for (rules, default, expected) in cases {
            let router = Router::new(&config_with(rules, default)).unwrap();
            assert_eq!(
                router.select("socks", Network::Tcp, &domain("example.test", 443)),
                expected
            );
        }
    }

    #[test]
    fn each_field_matches_any_value_and_port_endpoints_are_inclusive() {
        let cases = [
            (
                json!({"inbounds": ["other", "socks"], "outbound": "deny"}),
                "socks",
                Network::Tcp,
                domain("example.test", 443),
                true,
            ),
            (
                json!({"inbounds": ["other", "socks"], "outbound": "deny"}),
                "other",
                Network::Tcp,
                domain("example.test", 443),
                true,
            ),
            (
                json!({"inbounds": ["other"], "outbound": "deny"}),
                "socks",
                Network::Tcp,
                domain("example.test", 443),
                false,
            ),
            (
                json!({"networks": ["tcp", "udp"], "outbound": "deny"}),
                "socks",
                Network::Udp,
                domain("example.test", 443),
                true,
            ),
            (
                json!({"networks": ["udp"], "outbound": "deny"}),
                "socks",
                Network::Tcp,
                domain("example.test", 443),
                false,
            ),
            (
                json!({"domains": ["other.test", "EXAMPLE.Test."], "outbound": "deny"}),
                "socks",
                Network::Tcp,
                domain("example.TEST", 443),
                true,
            ),
            (
                json!({"domains": ["other.test", "example.test"], "outbound": "deny"}),
                "socks",
                Network::Tcp,
                domain("OTHER.Test.", 443),
                true,
            ),
            (
                json!({"domains": ["example.test"], "outbound": "deny"}),
                "socks",
                Network::Tcp,
                domain("sub.example.test", 443),
                false,
            ),
            (
                json!({"domains": ["example.test"], "outbound": "deny"}),
                "socks",
                Network::Tcp,
                domain("notexample.test", 443),
                false,
            ),
            (
                json!({"ip_cidrs": ["192.0.2.0/24", "2001:db8::/32"], "outbound": "deny"}),
                "socks",
                Network::Tcp,
                ip("192.0.2.1", 443),
                true,
            ),
            (
                json!({"ip_cidrs": ["192.0.2.0/24", "2001:db8::/32"], "outbound": "deny"}),
                "socks",
                Network::Udp,
                ip("2001:db8::1", 443),
                true,
            ),
            (
                json!({"ip_cidrs": ["192.0.2.0/24", "2001:db8::/32"], "outbound": "deny"}),
                "socks",
                Network::Udp,
                ip("198.51.100.1", 443),
                false,
            ),
            (
                json!({"ports": [{"start": 80, "end": 80}, {"start": 440, "end": 443}], "outbound": "deny"}),
                "socks",
                Network::Tcp,
                domain("example.test", 80),
                true,
            ),
            (
                json!({"ports": [{"start": 80, "end": 80}, {"start": 440, "end": 443}], "outbound": "deny"}),
                "socks",
                Network::Tcp,
                domain("example.test", 440),
                true,
            ),
            (
                json!({"ports": [{"start": 80, "end": 80}, {"start": 440, "end": 443}], "outbound": "deny"}),
                "socks",
                Network::Tcp,
                domain("example.test", 443),
                true,
            ),
            (
                json!({"ports": [{"start": 80, "end": 80}, {"start": 440, "end": 443}], "outbound": "deny"}),
                "socks",
                Network::Tcp,
                domain("example.test", 439),
                false,
            ),
            (
                json!({"ports": [{"start": 80, "end": 80}, {"start": 440, "end": 443}], "outbound": "deny"}),
                "socks",
                Network::Tcp,
                domain("example.test", 444),
                false,
            ),
        ];
        for (rule, inbound, network, target, matches) in cases {
            let description = rule.to_string();
            let router = Router::new(&config_with(json!([rule]), "allow")).unwrap();
            let expected = if matches {
                OutboundKind::Reject
            } else {
                OutboundKind::Direct
            };
            assert_eq!(
                router.select(inbound, network, &target),
                expected,
                "{description} {target:?}"
            );
        }
    }

    #[test]
    fn conditions_are_anded_across_every_combination() {
        let domain_router = Router::new(&config_with(
            json!([{
                "inbounds": ["socks"], "networks": ["udp"], "domains": ["EXAMPLE.test."],
                "ports": [{"start": 53, "end": 53}], "outbound": "deny"
            }]),
            "allow",
        ))
        .unwrap();
        let ip_router = Router::new(&config_with(
            json!([{
                "inbounds": ["socks"], "networks": ["udp"], "ip_cidrs": ["192.0.2.0/24"],
                "ports": [{"start": 53, "end": 53}], "outbound": "deny"
            }]),
            "allow",
        ))
        .unwrap();
        for mask in 0..16 {
            let inbound = if mask & 1 != 0 { "socks" } else { "other" };
            let network = if mask & 2 != 0 {
                Network::Udp
            } else {
                Network::Tcp
            };
            let name = if mask & 4 != 0 {
                "example.TEST."
            } else {
                "other.test"
            };
            let address = if mask & 4 != 0 {
                "192.0.2.7"
            } else {
                "198.51.100.7"
            };
            let port = if mask & 8 != 0 { 53 } else { 54 };
            let expected = if mask == 15 {
                OutboundKind::Reject
            } else {
                OutboundKind::Direct
            };
            assert_eq!(
                domain_router.select(inbound, network, &domain(name, port)),
                expected,
                "域名条件 {mask}"
            );
            assert_eq!(
                ip_router.select(inbound, network, &ip(address, port)),
                expected,
                "IP 条件 {mask}"
            );
        }
    }

    #[test]
    fn cidrs_only_see_original_ip_and_domains_never_match_ip_literals() {
        let router = Router::new(&config_with(
            json!([{
                "ip_cidrs": ["0.0.0.0/0", "::/0"], "outbound": "deny"
            }]),
            "allow",
        ))
        .unwrap();
        for target in [
            domain("localhost", 80),
            domain("192.0.2.1", 80),
            domain("::1", 80),
        ] {
            assert_eq!(
                router.select("socks", Network::Tcp, &target),
                OutboundKind::Direct
            );
        }
        for target in [ip("127.0.0.1", 80), ip("::1", 80)] {
            assert_eq!(
                router.select("socks", Network::Tcp, &target),
                OutboundKind::Reject
            );
        }
        let router = Router::new(&config_with(
            json!([{
                "domains": ["192.0.2.1"], "outbound": "deny"
            }]),
            "allow",
        ))
        .unwrap();
        assert_eq!(
            router.select("socks", Network::Tcp, &ip("192.0.2.1", 80)),
            OutboundKind::Direct
        );
        assert_eq!(
            router.select("socks", Network::Tcp, &domain("192.0.2.1", 80)),
            OutboundKind::Reject
        );
    }

    #[test]
    fn simultaneous_domain_and_ip_conditions_do_not_become_or() {
        let router = Router::new(&config_with(
            json!([{
                "domains": ["localhost"], "ip_cidrs": ["127.0.0.0/8"], "outbound": "deny"
            }]),
            "allow",
        ))
        .unwrap();
        for target in [domain("localhost", 80), ip("127.0.0.1", 80)] {
            assert_eq!(
                router.select("socks", Network::Tcp, &target),
                OutboundKind::Direct
            );
        }
    }

    #[test]
    fn address_and_port_boundaries_are_matched_without_io() {
        let router = Router::new(&config_with(
            json!([{
                "ip_cidrs": ["192.0.2.0/24", "2001:db8::/126"],
                "ports": [{"start": 0, "end": 65535}], "outbound": "deny"
            }]),
            "allow",
        ))
        .unwrap();
        for (address, expected) in [
            ("192.0.1.255", OutboundKind::Direct),
            ("192.0.2.0", OutboundKind::Reject),
            ("192.0.2.255", OutboundKind::Reject),
            ("192.0.3.0", OutboundKind::Direct),
            ("2001:db8::", OutboundKind::Reject),
            ("2001:db8::3", OutboundKind::Reject),
            ("2001:db8::4", OutboundKind::Direct),
        ] {
            for port in [0, 65535] {
                assert_eq!(
                    router.select("socks", Network::Udp, &ip(address, port)),
                    expected
                );
            }
        }
    }

    #[test]
    fn router_owns_a_validated_snapshot() {
        let mut config = config_with(
            json!([{"domains": ["example.test"], "outbound": "deny"}]),
            "allow",
        );
        let router = Router::new(&config).unwrap().clone();
        config.route.rules.clear();
        config.route.default = "missing".to_owned();
        config.outbounds.clear();
        assert_eq!(
            router.select("socks", Network::Tcp, &domain("EXAMPLE.TEST.", 80)),
            OutboundKind::Reject
        );
        assert_eq!(
            router.select("socks", Network::Tcp, &domain("other.test", 80)),
            OutboundKind::Direct
        );
        assert!(Router::new(&config).is_err());
    }

    #[test]
    fn constructor_rejects_invalid_programmatically_modified_config() {
        let base = config_with(json!([{"outbound": "deny"}]), "allow");
        let mut cases = Vec::new();
        let mut config = base.clone();
        config.route.default = "missing".to_owned();
        cases.push(config);
        let mut config = base.clone();
        config.route.rules[0].outbound = "missing".to_owned();
        cases.push(config);
        let mut config = base.clone();
        config.route.rules[0].inbounds.push("missing".to_owned());
        cases.push(config);
        let mut config = base;
        config.limits.max_handshakes = 0;
        cases.push(config);
        for config in cases {
            assert!(Router::new(&config).is_err());
        }
    }

    #[test]
    fn proxy_outbound_is_selected_with_parsed_endpoint() {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
                "outbounds": [
                    {"type": "direct", "tag": "allow"},
                    {
                        "type": "socks5", "tag": "up",
                        "endpoint": "[2001:db8::1]:1080",
                        "username": "alice", "password": "s3cret"
                    }
                ],
                "route": {"default": "allow", "rules": [{"outbound": "up", "networks": ["tcp"]}]}
            })
            .to_string(),
        )
        .unwrap();
        let router = Router::new(&config).unwrap();
        let selected = router.select_outbound("socks", Network::Tcp, &domain("example.com", 443));
        assert_eq!(selected.kind, OutboundKind::Socks5);
        let proxy = selected.proxy.expect("应带上游代理");
        assert_eq!(proxy.endpoint.port, 1080);
        assert_eq!(
            proxy.endpoint.host,
            Host::Ip("2001:db8::1".parse().unwrap())
        );
        let debug = format!("{proxy:?}");
        assert!(
            !debug.contains("alice") && !debug.contains("s3cret"),
            "{debug}"
        );
        // UDP 规则未匹配时回落到 default，不沿用 TCP 的代理选择。
        let udp = router.select_outbound("socks", Network::Udp, &domain("example.com", 443));
        assert_eq!(udp.kind, OutboundKind::Direct);
        assert!(udp.proxy.is_none());
    }

    #[test]
    fn domain_suffix_and_keyword_rules_match() {
        let router = Router::new(&config_with(
            json!([
                {"outbound": "deny", "domain_suffix": [".example.com"]},
                {"outbound": "deny", "domain_keyword": ["tracker"]}
            ]),
            "allow",
        ))
        .unwrap();
        for (name, expected) in [
            ("a.example.com", OutboundKind::Reject),
            ("EXAMPLE.COM.", OutboundKind::Reject),
            ("stats.tracker.test", OutboundKind::Reject),
            ("example.net", OutboundKind::Direct),
            ("stats.example.net", OutboundKind::Direct),
        ] {
            assert_eq!(
                router.select("socks", Network::Tcp, &domain(name, 443)),
                expected,
                "{name}"
            );
            assert_eq!(
                router.select("socks", Network::Udp, &domain(name, 53)),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn selector_groups_resolve_to_their_default_or_first_member() {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
                "outbounds": [
                    {"type": "direct", "tag": "direct"},
                    {"type": "reject", "tag": "reject"},
                    {"type": "socks5", "tag": "proxy", "endpoint": "127.0.0.1:1081"},
                    {"type": "selector", "tag": "manual", "outbounds": ["reject", "proxy"], "default": "proxy"},
                    {"type": "selector", "tag": "first", "outbounds": ["reject", "proxy"]},
                    {"type": "selector", "tag": "nested", "outbounds": ["manual"]}
                ],
                "route": {
                    "default": "nested",
                    "rules": [{"domains": ["first.test"], "outbound": "first"}]
                }
            })
            .to_string(),
        )
        .unwrap();
        let router = Router::new(&config).unwrap();
        // nested → manual → default proxy
        let selected = router.select_outbound("socks", Network::Tcp, &domain("a.test", 80));
        assert_eq!(selected.kind, OutboundKind::Socks5);
        assert!(selected.proxy.is_some());
        // first → 第一项 reject
        assert_eq!(
            router.select("socks", Network::Tcp, &domain("first.test", 80)),
            OutboundKind::Reject
        );
    }

    #[test]
    fn selector_configuration_is_validated() {
        let parse = |outbounds: Value, default: &str| {
            Config::from_json(
                &json!({
                    "version": 1,
                    "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
                    "outbounds": outbounds,
                    "route": {"default": default}
                })
                .to_string(),
            )
        };
        assert!(
            parse(
                json!([
                    {"type": "direct", "tag": "a"},
                    {"type": "selector", "tag": "g", "outbounds": []}
                ]),
                "g"
            )
            .is_err()
        );
        assert!(
            parse(
                json!([
                    {"type": "direct", "tag": "a"},
                    {"type": "selector", "tag": "g", "outbounds": ["missing"]}
                ]),
                "g"
            )
            .is_err()
        );
        assert!(
            parse(
                json!([
                    {"type": "direct", "tag": "a"},
                    {"type": "selector", "tag": "g", "outbounds": ["a"], "default": "missing"}
                ]),
                "g"
            )
            .is_err()
        );
        assert!(
            parse(
                json!([
                    {"type": "direct", "tag": "a"},
                    {"type": "selector", "tag": "g", "outbounds": ["a", "a"]}
                ]),
                "g"
            )
            .is_err()
        );
        assert!(
            parse(
                json!([
                    {"type": "direct", "tag": "a"},
                    {"type": "selector", "tag": "g", "outbounds": ["g"]}
                ]),
                "g"
            )
            .is_err()
        );
        assert!(
            parse(
                json!([
                    {"type": "direct", "tag": "a"},
                    {"type": "selector", "tag": "g", "outbounds": ["h"]},
                    {"type": "selector", "tag": "h", "outbounds": ["g"]}
                ]),
                "g"
            )
            .is_err()
        );
        assert!(
            parse(
                json!([
                    {"type": "direct", "tag": "a", "outbounds": ["a"]},
                    {"type": "selector", "tag": "g", "outbounds": ["a"]}
                ]),
                "g"
            )
            .is_err()
        );
        assert!(
            parse(
                json!([
                    {"type": "direct", "tag": "a"},
                    {"type": "selector", "tag": "g", "outbounds": ["a"]}
                ]),
                "g"
            )
            .is_ok()
        );
    }

    #[test]
    fn urltest_groups_start_on_their_first_member() {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
                "outbounds": [
                    {"type": "direct", "tag": "a"},
                    {"type": "socks5", "tag": "b", "endpoint": "127.0.0.1:1081"},
                    {
                        "type": "urltest",
                        "tag": "auto",
                        "outbounds": ["a", "b"],
                        "probe": "127.0.0.1:9",
                        "interval_ms": 1000,
                        "tolerance_ms": 10,
                        "probe_timeout_ms": 500
                    }
                ],
                "route": {"default": "auto"}
            })
            .to_string(),
        )
        .unwrap();
        let router = Router::new(&config).unwrap();
        assert_eq!(router.urltest_groups().len(), 1);
        assert_eq!(router.urltest_groups()[0].members().len(), 2);
        let selected = router.select_outbound("socks", Network::Tcp, &domain("a.test", 80));
        assert_eq!(selected.kind, OutboundKind::Direct);
        assert!(selected.proxy.is_none());
    }

    #[test]
    fn urltest_configuration_is_validated() {
        let parse = |outbounds: Value, default: &str| {
            Config::from_json(
                &json!({
                    "version": 1,
                    "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
                    "outbounds": outbounds,
                    "route": {"default": default}
                })
                .to_string(),
            )
        };
        let base = |extra: Value| {
            let mut outbound = json!({"type": "urltest", "tag": "g", "outbounds": ["a"]});
            if let (Some(object), Some(extra)) = (outbound.as_object_mut(), extra.as_object()) {
                for (key, value) in extra {
                    object.insert(key.clone(), value.clone());
                }
            }
            json!([{"type": "direct", "tag": "a"}, outbound])
        };
        // 缺少 probe
        assert!(parse(base(json!({})), "g").is_err());
        // probe 不是 HOST:PORT
        assert!(parse(base(json!({"probe": "127.0.0.1"})), "g").is_err());
        // 空成员
        assert!(
            parse(
                json!([
                    {"type": "direct", "tag": "a"},
                    {"type": "urltest", "tag": "g", "outbounds": [], "probe": "127.0.0.1:9"}
                ]),
                "g"
            )
            .is_err()
        );
        // default 仅适用于 selector
        assert!(parse(base(json!({"probe": "127.0.0.1:9", "default": "a"})), "g").is_err());
        // 探测参数越界
        assert!(
            parse(
                base(json!({"probe": "127.0.0.1:9", "interval_ms": 999})),
                "g"
            )
            .is_err()
        );
        assert!(
            parse(
                base(json!({"probe": "127.0.0.1:9", "tolerance_ms": 60001})),
                "g"
            )
            .is_err()
        );
        assert!(
            parse(
                base(json!({"probe": "127.0.0.1:9", "probe_timeout_ms": 99})),
                "g"
            )
            .is_err()
        );
        // 直接嵌套 urltest
        assert!(
            parse(
                json!([
                    {"type": "direct", "tag": "a"},
                    {"type": "urltest", "tag": "inner", "outbounds": ["a"], "probe": "127.0.0.1:9"},
                    {"type": "urltest", "tag": "g", "outbounds": ["inner"], "probe": "127.0.0.1:9"}
                ]),
                "g"
            )
            .is_err()
        );
        // selector 与 urltest 之间的循环
        assert!(
            parse(
                json!([
                    {"type": "direct", "tag": "a"},
                    {"type": "urltest", "tag": "g", "outbounds": ["s"], "probe": "127.0.0.1:9"},
                    {"type": "selector", "tag": "s", "outbounds": ["g"]}
                ]),
                "g"
            )
            .is_err()
        );
        // 非组出站配置 probe
        assert!(
            parse(
                json!([
                    {"type": "direct", "tag": "a", "probe": "127.0.0.1:9"},
                    {"type": "urltest", "tag": "g", "outbounds": ["a"], "probe": "127.0.0.1:9"}
                ]),
                "g"
            )
            .is_err()
        );
        assert!(parse(base(json!({"probe": "127.0.0.1:9"})), "g").is_ok());
    }

    #[test]
    fn resolved_addresses_only_affect_the_second_pass() {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
                "outbounds": [{"type": "direct", "tag": "allow"}, {"type": "reject", "tag": "deny"}],
                "route": {
                    "default": "allow",
                    "domain_strategy": "ip-if-non-match",
                    "rules": [{
                        "inbounds": ["socks"],
                        "ip_cidrs": ["192.0.2.0/24"],
                        "outbound": "deny"
                    }]
                }
            })
            .to_string(),
        )
        .unwrap();
        let router = Router::new(&config).unwrap();
        let target = domain("example.test", 443);
        assert_eq!(router.domain_strategy(), DomainStrategy::IpIfNonMatch);
        // 首轮不解析域名，IP 规则不命中。
        let first = router.select_outbound("socks", Network::Tcp, &target);
        assert!(!first.matched);
        assert_eq!(first.kind, OutboundKind::Direct);
        assert!(router.has_ip_candidates("socks", Network::Tcp, &target));
        assert!(!router.has_ip_candidates("other", Network::Tcp, &target));
        // 第二轮使用解析结果；没有解析结果时仍不命中。
        let resolved: Vec<IpAddr> = vec!["192.0.2.7".parse().unwrap()];
        let second = router.select_with("socks", Network::Tcp, &target, Some(&resolved));
        assert!(second.matched);
        assert_eq!(second.kind, OutboundKind::Reject);
        assert_eq!(
            router
                .select_with("socks", Network::Tcp, &target, None)
                .kind,
            OutboundKind::Direct
        );
    }

    #[test]
    fn via_chain_is_compiled_and_cycles_are_rejected() {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
                "outbounds": [
                    {"type": "socks5", "tag": "last", "endpoint": "127.0.0.1:1083"},
                    {"type": "socks5", "tag": "middle", "endpoint": "127.0.0.1:1082", "via": "last"},
                    {"type": "http", "tag": "first", "endpoint": "127.0.0.1:1081", "via": "middle"}
                ],
                "route": {"default": "first"}
            })
            .to_string(),
        )
        .unwrap();
        let router = Router::new(&config).unwrap();
        let selected = router.select_outbound("socks", Network::Tcp, &domain("example.com", 443));
        let first = selected.proxy.expect("链式出站");
        assert_eq!(first.endpoint.port, 1081);
        let middle = first.via.as_deref().expect("上一跳");
        assert_eq!(middle.endpoint.port, 1082);
        let last = middle.via.as_deref().expect("最近一跳");
        assert_eq!(last.endpoint.port, 1083);
        assert!(last.via.is_none());
        check_outbounds(&config).unwrap();

        let cyclic: Config = serde_json::from_value(json!({
            "version": 1,
            "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
            "outbounds": [
                {"type": "socks5", "tag": "a", "endpoint": "127.0.0.1:1081", "via": "b"},
                {"type": "socks5", "tag": "b", "endpoint": "127.0.0.1:1082", "via": "a"}
            ],
            "route": {"default": "a"}
        }))
        .unwrap();
        assert!(cyclic.validate().is_err());
        assert!(Router::new(&cyclic).is_err());
    }

    #[test]
    fn outbound_tls_trust_anchor_is_loaded() {
        let directory = tempfile::tempdir().unwrap();
        let key = rcgen::generate_simple_self_signed(vec!["proxy.example".to_owned()]).unwrap();
        let ca = directory.path().join("ca.pem");
        std::fs::write(&ca, key.cert.pem()).unwrap();
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
                "outbounds": [{
                    "type": "socks5", "tag": "up", "endpoint": "127.0.0.1:1080",
                    "tls": {"ca_file": ca.to_str().unwrap(), "server_name": "proxy.example"}
                }],
                "route": {"default": "up"}
            })
            .to_string(),
        )
        .unwrap();
        let router = Router::new(&config).unwrap();
        let selected = router.select_outbound("socks", Network::Tcp, &domain("example.com", 443));
        let proxy = selected.proxy.expect("应带上游代理");
        assert!(proxy.tls.is_some(), "TLS 配置应加载成功");
        check_outbounds(&config).unwrap();
    }
}

#[cfg(test)]
mod private_and_invert_tests {
    use super::*;
    use crate::config::Config;

    fn router(rules: serde_json::Value) -> Router {
        let config = Config::from_json(
            &serde_json::json!({
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "in", "listen": "127.0.0.1:1080"}],
                "outbounds": [
                    {"tag": "direct", "type": "direct"},
                    {"tag": "proxy", "type": "direct"}
                ],
                "route": {"rules": rules, "default": "direct"}
            })
            .to_string(),
        )
        .expect("配置应合法");
        Router::new(&config).expect("路由应可编译")
    }

    /// 返回命中的出站 tag；两个出站都是 direct，只能靠 `matched` 与位置区分，
    /// 因此这里直接比对 `matched` 与规则序号。
    fn select(router: &Router, host: &str) -> bool {
        let target = Target {
            host: Host::parse(host).expect("目标合法"),
            port: 443,
        };
        router.select_outbound("in", Network::Tcp, &target).matched
    }

    #[test]
    fn ip_is_private_matches_upstream_is_public_addr_negation() {
        // 对照 sing-box v1.14.4 `!N.IsPublicAddr`：IsPrivate || IsLoopback ||
        // IsMulticast || IsLinkLocalUnicast || IsInterfaceLocalMulticast ||
        // IsUnspecified。Go `netip.IsPrivate` 只含 RFC1918 与 fc00::/7。
        let router = router(serde_json::json!([
            {"ip_is_private": true, "outbound": "proxy"}
        ]));
        for host in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "224.0.0.1",
            "239.1.2.3",
            "169.254.1.1",
            "0.0.0.0",
        ] {
            assert!(select(&router, host), "{host} 应视为非公网");
        }
        // CGNAT 不在 Go `IsPrivate` 内：上游把 100.64.0.0/10 当公网。
        for host in ["8.8.8.8", "1.1.1.1", "100.64.0.1", "100.127.255.254"] {
            assert!(!select(&router, host), "{host} 应视为公网");
        }
    }

    #[test]
    fn ip_is_private_covers_ipv6_ula_link_local_and_multicast() {
        let router = router(serde_json::json!([
            {"ip_is_private": true, "outbound": "proxy"}
        ]));
        for host in [
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "ff01::1",
        ] {
            assert!(select(&router, host), "{host} 应视为非公网");
        }
        assert!(
            !select(&router, "2001:4860:4860::8888"),
            "公网 IPv6 不应命中"
        );
    }

    #[test]
    fn invert_flips_only_that_rule() {
        let router = router(serde_json::json!([
            {"domain_suffix": ["internal.example"], "invert": true, "outbound": "proxy"},
            {"domain_suffix": ["corp.example"], "outbound": "direct"}
        ]));
        // 不匹配 internal.example 的域名命中 invert 后的规则。
        assert!(select(&router, "public.example.com"));
        // 匹配 internal.example 时不命中第一条，继续走第二条。
        assert!(!select(&router, "a.internal.example"));
        // 后缀规则的普通语义不受影响：命中第二条，但第一条 invert 已先命中。
        assert!(select(&router, "b.corp.example"));
    }

    #[test]
    fn invert_without_conditions_is_rejected() {
        let error = Config::from_json(
            &serde_json::json!({
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "in", "listen": "127.0.0.1:1080"}],
                "outbounds": [{"tag": "direct", "type": "direct"}],
                "route": {"rules": [{"invert": true, "outbound": "direct"}], "default": "direct"}
            })
            .to_string(),
        )
        .expect_err("必须拒绝");
        assert!(format!("{error}").contains("invert"), "{error}");
    }
}

#[cfg(test)]
mod domain_regex_tests {
    use super::*;
    use crate::config::Config;

    fn config_with_rule(rule: serde_json::Value) -> String {
        serde_json::json!({
            "version": 1,
            "inbounds": [{"type": "socks5", "tag": "in", "listen": "127.0.0.1:1080"}],
            "outbounds": [{"tag": "direct", "type": "direct"}],
            "route": {"rules": [rule], "default": "direct"}
        })
        .to_string()
    }

    fn hits(rule: serde_json::Value, host: &str) -> bool {
        let config = Config::from_json(&config_with_rule(rule)).expect("配置应合法");
        let router = Router::new(&config).expect("路由应可编译");
        let target = Target {
            host: Host::parse(host).expect("目标合法"),
            port: 443,
        };
        router.select_outbound("in", Network::Tcp, &target).matched
    }

    #[test]
    fn domain_regex_matches_like_upstream_re2() {
        let rule = serde_json::json!({"domain_regex": ["^stun\\..+", "\\.example\\.org$"], "outbound": "direct"});
        assert!(hits(rule.clone(), "stun.l.google.com"));
        assert!(hits(rule.clone(), "api.example.org"));
        assert!(!hits(rule, "example.org"));
    }

    #[test]
    fn domain_regex_is_case_insensitive_because_domains_are_lowercased() {
        let rule =
            serde_json::json!({"domain_regex": ["^API\\.example\\.com$"], "outbound": "direct"});
        // 域名在匹配前统一小写，因此大写正则不会命中；这与 sing-box 的行为一致。
        assert!(!hits(rule, "api.example.com"));
    }

    #[test]
    fn invalid_domain_regex_is_rejected_at_load_time() {
        let error = Config::from_json(&config_with_rule(
            serde_json::json!({"domain_regex": ["(unclosed"], "outbound": "direct"}),
        ))
        .expect_err("非法正则必须拒绝");
        assert!(format!("{error}").contains("domain_regex"), "{error}");
    }
}

#[cfg(test)]
mod udp_reverse_tests {
    use super::*;
    use serde_json::json;

    /// `reverse` 出站的 `proxy` 为空，但它是独立上游，不是直连。
    ///
    /// 此前 dokodemo / TUIC / Hysteria2 / Snell / Shadowsocks 的 UDP 快路径
    /// 都用 `proxy.is_some()` 判断是否走代理，把 reverse 当成本地直连，
    /// 结果是反向目标被当普通目标发出去。
    #[test]
    fn reverse_is_not_direct_in_udp_fast_paths() {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
                "outbounds": [
                    {"type": "direct", "tag": "direct"},
                    {"type": "reverse", "tag": "portal", "domain": "v1.rvs.cool"}
                ],
                "route": {"default": "direct", "rules": [
                    {"domains": ["portal.test"], "outbound": "portal"}
                ]}
            })
            .to_string(),
        )
        .unwrap();
        let router = Router::new(&config).unwrap();
        let target = Target {
            host: Host::Domain("portal.test".to_owned()),
            port: 1234,
        };
        let selected = router.select_outbound("socks", Network::Udp, &target);
        assert!(selected.proxy.is_none());
        assert_eq!(
            selected.udp_proxied().unwrap_err().kind(),
            std::io::ErrorKind::Unsupported,
            "UDP 快路径必须对 reverse 失败关闭，不能静默直连"
        );

        let direct = router.select_outbound(
            "socks",
            Network::Udp,
            &Target {
                host: Host::Ip("127.0.0.1".parse().unwrap()),
                port: 1234,
            },
        );
        assert!(!direct.udp_proxied().unwrap());
    }
}

#[cfg(test)]
mod mux_udp_reverse_tests {
    use super::*;
    use serde_json::json;

    /// Mux 的 UDP 快路径同样不能把 `reverse` 当直连。
    ///
    /// 这正是 dokodemo / TUIC / Hysteria2 / Snell / SS 已修过、但 Mux 漏掉的
    /// 同一类问题：`reverse` 的 `proxy` 为空，只看 `.proxy` 就会静默直连。
    #[test]
    fn mux_udp_rejects_reverse_instead_of_dialing_direct() {
        let config = Config::from_json(
            &json!({
                "version": 1,
                "inbounds": [{"type": "socks5", "tag": "socks", "listen": "127.0.0.1:0"}],
                "outbounds": [
                    {"type": "direct", "tag": "direct"},
                    {"type": "reverse", "tag": "portal", "domain": "v1.rvs.cool"}
                ],
                "route": {"default": "direct", "rules": [
                    {"domains": ["portal.test"], "outbound": "portal"}
                ]}
            })
            .to_string(),
        )
        .unwrap();
        let router = Router::new(&config).unwrap();
        let selected = router.select_outbound(
            "socks",
            Network::Udp,
            &Target {
                host: Host::Domain("portal.test".to_owned()),
                port: 443,
            },
        );
        assert!(
            selected.proxy.is_none(),
            "reverse 出站不应带 proxy，这正是它会被误判为直连的原因"
        );
        assert!(
            selected.udp_proxied().is_err(),
            "Mux UDP 必须对 reverse 失败关闭"
        );
    }
}
