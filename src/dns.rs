use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use hickory_resolver::{
    Resolver, TokioResolver,
    config::{ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
    proto::{
        op::{Message, Query, ResponseCode},
        rr::{Name, RData, RecordType},
    },
};
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsConnector;

use crate::{
    config::{DnsConfig, DnsServer},
    route::normalize_domain,
    session::{Host, Target},
    tls,
};

/// DNS 查询后端。
///
/// 明文服务器继续使用 hickory 的 UDP 解析器；DoT/DoH 使用本仓库既有的
/// rustls 与 h2 直接实现。两种方式不在同一配置列表中混用，见
/// [`DnsConfig::server_endpoints`]。
#[derive(Clone)]
#[allow(clippy::large_enum_variant)] // 配置期构造一次，运行期只匹配；装箱只多一层间接。 
enum Backend {
    Hickory(TokioResolver),
    Encrypted(Encrypted),
    /// 并发查询多个单服务器后端，首个成功结果生效。
    Race(Vec<Backend>),
}

#[derive(Clone)]
struct Encrypted {
    servers: Vec<DnsServer>,
    /// DoT 使用的基础配置；DoH 在克隆后追加 `h2` ALPN。
    tls: Arc<ClientConfig>,
    /// 证书校验名与 SNI；省略时按每个服务器的 IP 地址校验。
    server_name: Option<ServerName<'static>>,
}

/// 加密 DNS 的本地缓存上限与最短/最长缓存时间。
///
/// hickory 自身带缓存；DoT/DoH 直接实现，需要缓存以避免 UDP 每包查询。
const CACHE_ENTRIES: usize = 1024;
const CACHE_MIN_TTL: u32 = 1;
const CACHE_MAX_TTL: u32 = 3600;

struct CacheEntry {
    expires: Instant,
    addresses: Vec<IpAddr>,
}

/// 按域名选择后端的规则；匹配语义与路由规则一致。
struct Rule {
    matcher: DomainMatcher,
    backend: Backend,
}

struct DomainMatcher {
    domains: Vec<String>,
    suffixes: Vec<String>,
    keywords: Vec<String>,
}

impl DomainMatcher {
    fn matches(&self, domain: &str) -> bool {
        self.domains.iter().any(|item| item == domain)
            || self
                .suffixes
                .iter()
                .any(|suffix| crate::route::matches_domain_suffix(domain, suffix))
            || self
                .keywords
                .iter()
                .any(|keyword| domain.contains(keyword.as_str()))
    }
}

/// 克隆保留同一解析配置/缓存/查询预算快照，可由独立拨号工厂延迟解析，
/// 不需要强持有Context，也不会在连接池命中前提前查询。
#[derive(Clone)]
pub struct Dns {
    backend: Backend,
    rules: Arc<Vec<Rule>>,
    hosts: Arc<HashMap<String, Vec<IpAddr>>>,
    /// 键包含后端分组，避免不同服务器列表的缓存互相污染。
    cache: Arc<Mutex<HashMap<(usize, String), CacheEntry>>>,
    permits: Arc<Semaphore>,
    deadline: Duration,
}

fn udp_name_server(address: SocketAddr) -> NameServerConfig {
    let mut connection = ConnectionConfig::udp();
    connection.port = address.port();
    NameServerConfig::new(address.ip(), true, vec![connection])
}

fn default_options() -> ResolverOpts {
    let mut options = ResolverOpts::default();
    // 0.24 默认 IPv4 优先；0.26 改为 IPv6 优先。保持既有语义，避免
    // localhost/双栈目标在 UDP 首地址选择上发生兼容性变化。
    options.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
    options
}

fn resolver_from_config(
    config: ResolverConfig,
    options: ResolverOpts,
) -> anyhow::Result<TokioResolver> {
    Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(options)
        .build()
        .map_err(|_| anyhow::anyhow!("DNS 解析器初始化失败"))
}

fn system_resolver() -> anyhow::Result<TokioResolver> {
    let mut builder =
        TokioResolver::builder_tokio().map_err(|_| anyhow::anyhow!("无法读取系统 DNS 配置"))?;
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
    builder
        .build()
        .map_err(|_| anyhow::anyhow!("DNS 解析器初始化失败"))
}

/// 构建单 UDP 服务器的解析器；测试和调用方需要注入受控 DNS 时使用。
pub fn udp_resolver(address: SocketAddr, options: ResolverOpts) -> anyhow::Result<TokioResolver> {
    let mut config = ResolverConfig::default();
    config.add_name_server(udp_name_server(address));
    resolver_from_config(config, options)
}

/// 构建无上游服务器的解析器；仅用于目标已经是 IP、不会触发 DNS 的场景。
pub fn empty_resolver(options: ResolverOpts) -> anyhow::Result<TokioResolver> {
    resolver_from_config(ResolverConfig::default(), options)
}

/// 按服务器列表构建后端；空列表沿用系统配置。
/// 为并发规则构建单服务器后端列表。
fn build_race_backend(endpoints: Vec<DnsServer>, config: &DnsConfig) -> anyhow::Result<Backend> {
    if endpoints.len() <= 1 {
        return build_backend(endpoints, config);
    }
    let shares_encryption = endpoints
        .iter()
        .any(|endpoint| !matches!(endpoint, DnsServer::Udp(_)));
    let (tls, server_name) = if shares_encryption {
        let ca_file = config
            .ca_file
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("dns.ca_file 在配置 tls:// 或 https:// 服务器时必填"))?;
        let server_name = match &config.server_name {
            Some(name) => Some(tls::parse_server_name(name)?),
            None => None,
        };
        (Some(tls::client_config(ca_file)?), server_name)
    } else {
        (None, None)
    };
    let mut backends = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        match endpoint {
            DnsServer::Udp(address) => {
                backends.push(Backend::Hickory(udp_resolver(address, default_options())?));
            }
            endpoint => backends.push(Backend::Encrypted(Encrypted {
                servers: vec![endpoint],
                tls: tls.clone().expect("加密服务器共享 TLS 配置"),
                server_name: server_name.clone(),
            })),
        }
    }
    Ok(Backend::Race(backends))
}

fn build_backend(endpoints: Vec<DnsServer>, config: &DnsConfig) -> anyhow::Result<Backend> {
    if endpoints.is_empty() {
        return Ok(Backend::Hickory(system_resolver()?));
    }
    if endpoints
        .iter()
        .any(|endpoint| !matches!(endpoint, DnsServer::Udp(_)))
    {
        let ca_file = config
            .ca_file
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("dns.ca_file 在配置 tls:// 或 https:// 服务器时必填"))?;
        let server_name = match &config.server_name {
            Some(name) => Some(tls::parse_server_name(name)?),
            None => None,
        };
        return Ok(Backend::Encrypted(Encrypted {
            servers: endpoints,
            tls: tls::client_config(ca_file)?,
            server_name,
        }));
    }
    let mut resolver_config = ResolverConfig::default();
    for endpoint in endpoints {
        let DnsServer::Udp(address) = endpoint else {
            unreachable!("混合服务器已在配置校验时拒绝");
        };
        resolver_config.add_name_server(udp_name_server(address));
    }
    Ok(Backend::Hickory(resolver_from_config(
        resolver_config,
        default_options(),
    )?))
}

impl Dns {
    pub fn system(max_queries: usize, deadline: Duration) -> anyhow::Result<Self> {
        Ok(Self::new(system_resolver()?, max_queries, deadline))
    }

    /// 按配置构建解析器：无服务器配置时沿用系统配置，`hosts` 始终优先。
    pub fn from_config(
        config: Option<&DnsConfig>,
        max_queries: usize,
        deadline: Duration,
    ) -> anyhow::Result<Self> {
        let Some(config) = config else {
            return Self::system(max_queries, deadline);
        };
        let backend = build_backend(config.server_endpoints()?, config)?;
        let mut rules = Vec::with_capacity(config.rules.len());
        for rule in &config.rules {
            let endpoints = crate::config::parse_dns_servers(&rule.servers, "dns.rules[].servers")?;
            rules.push(Rule {
                matcher: DomainMatcher {
                    domains: rule
                        .domains
                        .iter()
                        .map(|domain| normalize_domain(domain))
                        .collect(),
                    suffixes: rule
                        .domain_suffix
                        .iter()
                        .map(|suffix| normalize_domain(suffix))
                        .collect(),
                    keywords: rule
                        .domain_keyword
                        .iter()
                        .map(|keyword| keyword.to_ascii_lowercase())
                        .collect(),
                },
                backend: if rule.race {
                    build_race_backend(endpoints, config)?
                } else {
                    build_backend(endpoints, config)?
                },
            });
        }
        let mut hosts: HashMap<String, Vec<IpAddr>> = HashMap::with_capacity(config.hosts.len());
        for (domain, values) in &config.hosts {
            let ips: Vec<IpAddr> = values
                .iter()
                .filter_map(|value| value.parse().ok())
                .collect();
            hosts.insert(normalize_domain(domain), ips);
        }
        Ok(Self {
            backend,
            rules: Arc::new(rules),
            hosts: Arc::new(hosts),
            cache: Arc::new(Mutex::new(HashMap::new())),
            permits: Arc::new(Semaphore::new(max_queries)),
            deadline,
        })
    }

    pub fn new(resolver: TokioResolver, max_queries: usize, deadline: Duration) -> Self {
        Self {
            backend: Backend::Hickory(resolver),
            rules: Arc::new(Vec::new()),
            hosts: Arc::new(HashMap::new()),
            cache: Arc::new(Mutex::new(HashMap::new())),
            permits: Arc::new(Semaphore::new(max_queries)),
            deadline,
        }
    }

    pub async fn resolve(&self, target: &Target) -> io::Result<Vec<SocketAddr>> {
        let domain = match &target.host {
            Host::Ip(ip) => return Ok(vec![SocketAddr::new(*ip, target.port)]),
            Host::Domain(domain) => domain,
        };
        if !self.hosts.is_empty() {
            let key = normalize_domain(domain);
            if let Some(ips) = self.hosts.get(&key) {
                let mut addresses = Vec::with_capacity(ips.len());
                for ip in ips {
                    let address = SocketAddr::new(*ip, target.port);
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
                return Ok(addresses);
            }
        }
        let _permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "DNS 并发上限"))?;
        let response = timeout(self.deadline, self.lookup(domain.as_str()))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS 超时"))??;
        let mut addresses = Vec::new();
        for ip in response {
            let addr = SocketAddr::new(ip, target.port);
            if !addresses.contains(&addr) {
                addresses.push(addr);
            }
        }
        if addresses.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "DNS 无地址"));
        }
        Ok(addresses)
    }

    fn backend_for(&self, domain: &str) -> (usize, &Backend) {
        for (index, rule) in self.rules.iter().enumerate() {
            if rule.matcher.matches(domain) {
                return (index + 1, &rule.backend);
            }
        }
        (0, &self.backend)
    }

    async fn lookup(&self, domain: &str) -> io::Result<Vec<IpAddr>> {
        let key = normalize_domain(domain);
        let (group, backend) = self.backend_for(&key);
        match backend {
            Backend::Hickory(resolver) => {
                let response = resolver
                    .lookup_ip(domain)
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "DNS 解析失败"))?;
                Ok(response.iter().collect())
            }
            Backend::Encrypted(encrypted) => {
                if let Some(addresses) = self.cache_get(group, &key) {
                    return Ok(addresses);
                }
                let (addresses, ttl) = Self::lookup_encrypted(encrypted, domain).await?;
                self.cache_put(group, key, &addresses, ttl);
                Ok(addresses)
            }
            Backend::Race(backends) => {
                if let Some(addresses) = self.cache_get(group, &key) {
                    return Ok(addresses);
                }
                let mut tasks = JoinSet::new();
                for backend in backends {
                    let backend = backend.clone();
                    let domain = domain.to_owned();
                    tasks.spawn(async move { Self::backend_lookup(&backend, &domain).await });
                }
                let mut last_error = None;
                while let Some(joined) = tasks.join_next().await {
                    match joined {
                        Ok(Ok((addresses, ttl))) if !addresses.is_empty() => {
                            tasks.abort_all();
                            self.cache_put(group, key, &addresses, ttl);
                            return Ok(addresses);
                        }
                        Ok(Ok(_)) => {
                            last_error =
                                Some(io::Error::new(io::ErrorKind::NotFound, "DNS 无地址"));
                        }
                        Ok(Err(error)) => last_error = Some(error),
                        Err(_) => {
                            last_error = Some(io::Error::other("DNS 查询任务异常"));
                        }
                    }
                }
                Err(last_error
                    .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS 无地址")))
            }
        }
    }

    fn cache_get(&self, group: usize, key: &str) -> Option<Vec<IpAddr>> {
        let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        let entry = cache.get(&(group, key.to_owned()))?;
        if entry.expires <= Instant::now() {
            cache.remove(&(group, key.to_owned()));
            return None;
        }
        Some(entry.addresses.clone())
    }

    fn cache_put(&self, group: usize, key: String, addresses: &[IpAddr], ttl: u32) {
        if addresses.is_empty() {
            return;
        }
        let ttl = ttl.clamp(CACHE_MIN_TTL, CACHE_MAX_TTL);
        let now = Instant::now();
        let mut cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        if cache.len() >= CACHE_ENTRIES {
            cache.retain(|_, entry| entry.expires > now);
            if cache.len() >= CACHE_ENTRIES {
                return;
            }
        }
        cache.insert(
            (group, key),
            CacheEntry {
                expires: now + Duration::from_secs(u64::from(ttl)),
                addresses: addresses.to_vec(),
            },
        );
    }

    /// 单个后端查询；并发模式使用，失败时返回错误。
    async fn backend_lookup(backend: &Backend, domain: &str) -> io::Result<(Vec<IpAddr>, u32)> {
        match backend {
            Backend::Hickory(resolver) => {
                let response = resolver
                    .lookup_ip(domain)
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "DNS 解析失败"))?;
                let addresses: Vec<IpAddr> = response.iter().collect();
                if addresses.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "DNS 无地址"));
                }
                // 用记录自身的剩余有效期。写死 60 秒会把 TTL=1 的答案复用到
                // 一分钟后：故障切换时客户端一直拿着旧地址。
                let ttl = response
                    .valid_until()
                    .saturating_duration_since(std::time::Instant::now())
                    .as_secs()
                    .min(u64::from(u32::MAX)) as u32;
                Ok((addresses, ttl))
            }
            Backend::Encrypted(encrypted) => Self::lookup_encrypted(encrypted, domain).await,
            Backend::Race(_) => Err(io::Error::other("DNS 并发后端不得嵌套")),
        }
    }

    /// 依次尝试给定加密服务器；任一服务器返回地址即成功。
    async fn lookup_encrypted(
        encrypted: &Encrypted,
        domain: &str,
    ) -> io::Result<(Vec<IpAddr>, u32)> {
        let name = Name::from_ascii(domain)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS 域名无效"))?;
        let mut last_error = None;
        for server in &encrypted.servers {
            let mut addresses = Vec::new();
            let mut errors = Vec::new();
            let mut ttl = u32::MAX;
            for record_type in [RecordType::A, RecordType::AAAA] {
                match query_server(encrypted, server, &name, record_type).await {
                    Ok((found, found_ttl)) => {
                        addresses.extend(found);
                        ttl = ttl.min(found_ttl);
                    }
                    Err(error) => errors.push(error),
                }
            }
            dedup(&mut addresses);
            if !addresses.is_empty() {
                // 没有任何有效 TTL 时使用 60 秒的保守值。
                let ttl = if ttl == u32::MAX { 60 } else { ttl };
                return Ok((addresses, ttl));
            }
            last_error = Some(
                errors
                    .pop()
                    .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS 无地址")),
            );
        }
        Err(last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS 无地址")))
    }
}

fn dedup(addresses: &mut Vec<IpAddr>) {
    let mut seen = Vec::with_capacity(addresses.len());
    addresses.retain(|ip| {
        if seen.contains(ip) {
            false
        } else {
            seen.push(*ip);
            true
        }
    });
}

async fn query_server(
    encrypted: &Encrypted,
    server: &DnsServer,
    name: &Name,
    record_type: RecordType,
) -> io::Result<(Vec<IpAddr>, u32)> {
    let (address, tls_name) = match server {
        DnsServer::Udp(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "加密 DNS 后端收到明文服务器",
            ));
        }
        DnsServer::Tls(address) | DnsServer::Https(address, _) => {
            (*address, server_name(encrypted, *address))
        }
    };
    let query = build_query(name, record_type)?;
    match server {
        DnsServer::Tls(_) => {
            dot_query(
                address,
                encrypted.tls.clone(),
                tls_name,
                &query,
                record_type,
            )
            .await
        }
        DnsServer::Https(_, path) => {
            doh_query(address, path, encrypted, tls_name, &query, record_type).await
        }
        DnsServer::Udp(_) => unreachable!(),
    }
}

/// 配置了 `server_name` 时所有服务器共用同一校验名，否则使用服务器 IP。
fn server_name(encrypted: &Encrypted, address: SocketAddr) -> ServerName<'static> {
    encrypted
        .server_name
        .clone()
        .unwrap_or_else(|| ServerName::IpAddress(address.ip().into()))
}

fn build_query(name: &Name, record_type: RecordType) -> io::Result<Vec<u8>> {
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name.clone(), record_type));
    message
        .to_vec()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS 查询编码失败"))
}

async fn dot_query(
    address: SocketAddr,
    tls_config: Arc<ClientConfig>,
    tls_name: ServerName<'static>,
    query: &[u8],
    record_type: RecordType,
) -> io::Result<(Vec<IpAddr>, u32)> {
    let stream = TcpStream::connect(address).await?;
    stream.set_nodelay(true)?;
    let mut stream = TlsConnector::from(tls_config)
        .connect(tls_name, stream)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS TLS 握手失败"))?;
    let length = u16::try_from(query.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS 查询过大"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(query).await?;
    stream.flush().await?;
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS TLS 响应为空",
        ));
    }
    let mut response = vec![0u8; length];
    stream.read_exact(&mut response).await?;
    parse_response(&response, record_type)
}

async fn doh_query(
    address: SocketAddr,
    path: &str,
    encrypted: &Encrypted,
    tls_name: ServerName<'static>,
    query: &[u8],
    record_type: RecordType,
) -> io::Result<(Vec<IpAddr>, u32)> {
    let stream = TcpStream::connect(address).await?;
    stream.set_nodelay(true)?;
    let mut config = (*encrypted.tls).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let stream = TlsConnector::from(Arc::new(config))
        .connect(tls_name, stream)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS HTTPS 握手失败"))?;
    let (mut client, connection) = h2::client::handshake(stream)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS HTTP/2 握手失败"))?;
    // 连接驱动与请求解耦；查询结束或超时取消时由守卫关闭连接，避免
    // 后台任务等待对方空闲超时。
    let cancel = tokio_util::sync::CancellationToken::new();
    let _cancel_on_drop = cancel.clone().drop_guard();
    let driver = cancel.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = driver.cancelled() => {}
            _ = connection => {}
        }
    });
    let authority = authority(encrypted, address)?;
    let uri = format!("https://{authority}{path}");
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/dns-message")
        .header(http::header::ACCEPT, "application/dns-message")
        .body(())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS HTTPS 请求无效"))?;
    let (response, mut send) = client
        .send_request(request, false)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS HTTPS 请求发送失败"))?;
    send.send_data(prost::bytes::Bytes::copy_from_slice(query), true)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS HTTPS 请求体发送失败"))?;
    let response = response
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS HTTPS 响应失败"))?;
    if response.status() != http::StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS HTTPS 响应状态非 200",
        ));
    }
    if let Some(content_type) = response.headers().get(http::header::CONTENT_TYPE)
        && !content_type
            .to_str()
            .is_ok_and(|value| value.starts_with("application/dns-message"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS HTTPS 响应内容类型无效",
        ));
    }
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS HTTPS 响应体读取失败"))?;
        if bytes.len() + chunk.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS HTTPS 响应过大",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    parse_response(&bytes, record_type)
}

/// HTTPS 请求的 `:authority`：优先使用配置的校验名，否则使用服务器地址。
fn authority(encrypted: &Encrypted, address: SocketAddr) -> io::Result<String> {
    let host = match &encrypted.server_name {
        Some(ServerName::DnsName(name)) => name.as_ref().to_owned(),
        Some(ServerName::IpAddress(ip)) => std::net::IpAddr::from(*ip).to_string(),
        _ => address.ip().to_string(),
    };
    if host.contains(':') && !host.starts_with('[') {
        Ok(format!("[{host}]:{}", address.port()))
    } else {
        Ok(format!("{host}:{}", address.port()))
    }
}

fn parse_response(bytes: &[u8], record_type: RecordType) -> io::Result<(Vec<IpAddr>, u32)> {
    let message = Message::from_vec(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS 响应解析失败"))?;
    if message.metadata.truncation {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "DNS 响应被截断"));
    }
    if message.metadata.response_code != ResponseCode::NoError {
        return Err(io::Error::new(io::ErrorKind::NotFound, "DNS 响应码非成功"));
    }
    let mut addresses = Vec::new();
    let mut ttl = u32::MAX;
    for record in &message.answers {
        match (record_type, &record.data) {
            (RecordType::A, RData::A(address)) => {
                addresses.push(IpAddr::V4(address.0));
                ttl = ttl.min(record.ttl);
            }
            (RecordType::AAAA, RData::AAAA(address)) => {
                addresses.push(IpAddr::V6(address.0));
                ttl = ttl.min(record.ttl);
            }
            _ => {}
        }
    }
    Ok((addresses, ttl))
}
