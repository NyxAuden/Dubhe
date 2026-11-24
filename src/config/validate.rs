//! 配置校验：跨入口/出站的引用、端口、协议组合与资源上限规则。
//!
//! 只做纯静态检查；证书读取、密钥匹配与监听准备留给运行器。

use super::*;

/// 两个监听 IP 是否会争用同一端口。
///
/// - 相同地址直接冲突；
/// - 同族里任一侧是未指定地址（`0.0.0.0` / `::`）时覆盖全族，与具体地址冲突；
/// - `::` 在双栈模式下还会占用 IPv4 端口（macOS 实测 `IPV6_V6ONLY=0`，
///   之后绑 `0.0.0.0:同端口` 直接 `EADDRINUSE`），因此 `::` 与任何 IPv4
///   地址也冲突。
///
/// 反过来，具体 IPv6 地址与具体 IPv4 地址不冲突。
fn overlapping(left: std::net::IpAddr, right: std::net::IpAddr) -> bool {
    use std::net::IpAddr::{V4, V6};
    if left == right {
        return true;
    }
    match (left, right) {
        (V4(a), V4(b)) => a.is_unspecified() || b.is_unspecified(),
        (V6(a), V6(b)) => a.is_unspecified() || b.is_unspecified(),
        // `::` 双栈时同时占用 IPv4。
        (V6(a), V4(_)) | (V4(_), V6(a)) => a.is_unspecified(),
    }
}

impl Config {
    /// 解析并执行纯静态校验；证书读取、密钥匹配和监听准备由运行器完成。
    pub fn from_json(input: &str) -> Result<Self> {
        let config: Self = serde_json::from_str(input).map_err(sanitize_json_error)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "version 仅支持版本 1");
        ensure!(!self.inbounds.is_empty(), "inbounds 不得为空");
        ensure!(!self.outbounds.is_empty(), "outbounds 不得为空");
        self.limits.validate()?;
        if let Some(id) = &self.deployment_id {
            ensure!(
                crate::apply::valid_deployment_id(id),
                "deployment_id 必须是 32 位小写十六进制"
            );
        }
        if let Some(api) = &self.api {
            ensure!(api.listen.ip().is_loopback(), "api.listen 必须是回环地址");
            ensure!(
                api.token_file.is_none() || api.token.is_empty(),
                "api.token 与 api.token_file 只能配置一个"
            );
            match &api.token_file {
                Some(path) => ensure!(!path.as_os_str().is_empty(), "api.token_file 不得为空"),
                None => validate_api_token(&api.token)?,
            }
        }
        if let Some(dns) = &self.dns {
            ensure!(dns.servers.len() <= 8, "dns.servers 最多 8 个");
            let endpoints = dns.server_endpoints()?;
            let mut encrypted = endpoints
                .iter()
                .any(|endpoint| !matches!(endpoint, DnsServer::Udp(_)));
            ensure!(dns.rules.len() <= 32, "dns.rules 最多 32 条");
            for (index, rule) in dns.rules.iter().enumerate() {
                ensure!(
                    !rule.servers.is_empty(),
                    "dns.rules[{index}].servers 不得为空"
                );
                ensure!(
                    rule.servers.len() <= 8,
                    "dns.rules[{index}].servers 最多 8 个"
                );
                let endpoints =
                    parse_dns_servers(&rule.servers, &format!("dns.rules[{index}].servers"))?;
                encrypted |= endpoints
                    .iter()
                    .any(|endpoint| !matches!(endpoint, DnsServer::Udp(_)));
                ensure!(
                    !(rule.domains.is_empty()
                        && rule.domain_suffix.is_empty()
                        && rule.domain_keyword.is_empty()),
                    "dns.rules[{index}] 至少需要一个域名匹配字段"
                );
                ensure!(
                    rule.domains.iter().all(|domain| valid_domain(domain)),
                    "dns.rules[{index}].domains 必须是非空的 ASCII 精确域名"
                );
                ensure!(
                    rule.domain_suffix
                        .iter()
                        .all(|suffix| valid_domain_fragment(suffix)),
                    "dns.rules[{index}].domain_suffix 必须是非空 ASCII 域名后缀"
                );
                ensure!(
                    rule.domain_keyword.iter().all(|keyword| !keyword.is_empty()
                        && keyword.is_ascii()
                        && !keyword.chars().any(char::is_whitespace)),
                    "dns.rules[{index}].domain_keyword 必须是非空 ASCII 关键字"
                );
            }
            ensure!(
                !encrypted || dns.ca_file.is_some(),
                "dns.ca_file 在配置 tls:// 或 https:// 服务器时必填"
            );
            ensure!(
                encrypted || dns.ca_file.is_none(),
                "dns.ca_file 仅适用于 tls:// 或 https:// 服务器"
            );
            ensure!(
                encrypted || dns.server_name.is_none(),
                "dns.server_name 仅适用于 tls:// 或 https:// 服务器"
            );
            if let Some(name) = &dns.server_name {
                ensure!(
                    !name.is_empty()
                        && name.len() <= 255
                        && name.is_ascii()
                        && !name.bytes().any(|byte| byte.is_ascii_whitespace()),
                    "dns.server_name 必须是合法的主机名或 IP 字面量"
                );
            }
            ensure!(dns.hosts.len() <= 4096, "dns.hosts 条目过多");
            for (domain, values) in &dns.hosts {
                let parsed = crate::session::Host::parse(domain);
                ensure!(
                    matches!(parsed, Some(crate::session::Host::Domain(_))),
                    "dns.hosts 的键必须是域名"
                );
                ensure!(
                    !values.is_empty() && values.len() <= 16,
                    "dns.hosts 值数量无效"
                );
                for value in values {
                    ensure!(
                        value.parse::<std::net::IpAddr>().is_ok(),
                        "dns.hosts 的值必须是 IP 地址"
                    );
                }
            }
        }

        let mut inbound_tags = HashSet::new();
        for (index, inbound) in self.inbounds.iter().enumerate() {
            ensure!(valid_tag(inbound.tag()), "inbounds[{index}].tag 格式无效");
            ensure!(
                inbound_tags.insert(inbound.tag()),
                "inbounds[{index}].tag 重复"
            );
            // 允许端口 0，供嵌入库及测试申请临时端口；监听冲突留到实际绑定阶段。
            match inbound {
                Inbound::Socks5 {
                    listen,
                    users,
                    allow_insecure,
                    ..
                } => {
                    validate_users(users, true, index)?;
                    ensure!(
                        !users.is_empty() || listen.ip().is_loopback() || *allow_insecure,
                        "inbounds[{index}] 非回环无认证 SOCKS5 必须显式设置 allow_insecure"
                    );
                }
                Inbound::Http {
                    listen,
                    users,
                    allow_insecure,
                    certificate,
                    private_key,
                    ..
                } => {
                    ensure!(
                        certificate.is_some() == private_key.is_some(),
                        "inbounds[{index}].certificate 和 private_key 必须成对配置"
                    );
                    validate_users(users, false, index)?;
                    ensure!(
                        !users.is_empty() || listen.ip().is_loopback() || *allow_insecure,
                        "inbounds[{index}] 非回环无认证 HTTP/Mixed 必须显式设置 allow_insecure"
                    );
                }
                Inbound::Mixed {
                    listen,
                    users,
                    allow_insecure,
                    certificate,
                    private_key,
                    ..
                } => {
                    ensure!(
                        certificate.is_some() == private_key.is_some(),
                        "inbounds[{index}].certificate 和 private_key 必须成对配置"
                    );
                    validate_users(users, false, index)?;
                    ensure!(
                        !users.is_empty() || listen.ip().is_loopback() || *allow_insecure,
                        "inbounds[{index}] 非回环无认证 HTTP/Mixed 必须显式设置 allow_insecure"
                    );
                }
                Inbound::Naive { users, .. } => {
                    ensure!(!users.is_empty(), "inbounds[{index}].users 不得为空");
                    validate_users(users, false, index)?;
                }
                Inbound::AnyTls {
                    users,
                    padding_scheme,
                    ..
                } => {
                    ensure!(!users.is_empty(), "inbounds[{index}].users 不得为空");
                    validate_users(users, false, index)?;
                    if let Some(raw) = padding_scheme {
                        crate::transport::anytls_padding::Scheme::parse(raw).map_err(|_| {
                            anyhow!("inbounds[{index}].padding_scheme无效或超出资源上限")
                        })?;
                    }
                }
                Inbound::Trojan {
                    users, fallbacks, ..
                } => {
                    ensure!(!users.is_empty(), "inbounds[{index}].users 不得为空");
                    validate_users(users, false, index)?;
                    fallback::validate(fallbacks, index)?;
                }
                Inbound::Vless {
                    users,
                    fallbacks,
                    decryption,
                    certificate,
                    private_key,
                    ..
                } => {
                    ensure!(!users.is_empty(), "inbounds[{index}].users 不得为空");
                    validate_vless_users(users, index)?;
                    fallback::validate(fallbacks, index)?;
                    ensure!(
                        certificate.is_some() == private_key.is_some(),
                        "inbounds[{index}].certificate 和 private_key 必须成对配置"
                    );
                    if certificate.is_none() {
                        // 明文 VLESS 没有 TLS 层，依赖 TLS 的选项必须失败关闭。
                        ensure!(
                            fallbacks.is_empty(),
                            "inbounds[{index}] 明文 VLESS 不支持 fallbacks"
                        );
                        ensure!(
                            users.iter().all(|user| user.flow == VlessFlow::None),
                            "inbounds[{index}] 明文 VLESS 不支持 Vision flow"
                        );
                    }
                    ensure!(
                        fallbacks.is_empty()
                            || users.iter().all(|user| user.flow == VlessFlow::None),
                        "inbounds[{index}] fallback 不能与 Vision flow 并存"
                    );
                    if let Some(value) = decryption
                        && vless_encryption::parse(value)?.is_some()
                    {
                        ensure!(
                            fallbacks.is_empty(),
                            "inbounds[{index}] decryption 不能与 fallbacks 并存"
                        );
                    }
                }
                Inbound::VlessReality {
                    users,
                    reality,
                    decryption,
                    ..
                } => {
                    ensure!(
                        (1..=1024).contains(&users.len()),
                        "inbounds[{index}].users 数量必须在1到1024之间"
                    );
                    validate_vless_users(users, index)?;
                    validate_vless_decryption(decryption.as_deref())?;
                    reality.prepare()?;
                }
                Inbound::VmessReality { users, reality, .. } => {
                    vmess::validate_users(users, index)?;
                    reality.prepare()?;
                }
                Inbound::TrojanReality { users, reality, .. } => {
                    ensure!(!users.is_empty(), "inbounds[{index}].users 不得为空");
                    validate_users(users, false, index)?;
                    reality.prepare()?;
                }
                Inbound::Shadowsocks {
                    method,
                    password,
                    users,
                    ..
                } => {
                    shadowsocks::prepare(*method, password, users.as_deref(), index)?;
                }
                Inbound::Vmess {
                    users,
                    certificate,
                    private_key,
                    ..
                } => {
                    vmess::validate_users(users, index)?;
                    ensure!(
                        certificate.is_some() == private_key.is_some(),
                        "inbounds[{index}].certificate 和 private_key 必须成对配置"
                    );
                }
                Inbound::VlessWs {
                    users,
                    allow_insecure_transport,
                    websocket,
                    certificate,
                    private_key,
                    reality,
                    decryption,
                    ..
                } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_vless_users(users, index)?;
                    validate_vless_decryption(decryption.as_deref())?;
                    ensure!(
                        users.iter().all(|user| user.flow == VlessFlow::None),
                        "inbounds[{index}].users 的 WebSocket VLESS flow 必须为空"
                    );
                    reject_reality_transport(reality.as_ref(), "WebSocket", index)?;
                    if !validate_reality_transport(
                        reality.as_ref(),
                        certificate.as_deref(),
                        private_key.as_deref(),
                        *allow_insecure_transport,
                        index,
                    )? {
                        websocket::validate_tls(
                            certificate.as_deref(),
                            private_key.as_deref(),
                            *allow_insecure_transport,
                            index,
                        )?;
                    }
                    websocket.validate()?;
                }
                Inbound::VmessWs {
                    users,
                    websocket,
                    certificate,
                    private_key,
                    reality,
                    ..
                } => {
                    vmess::validate_users(users, index)?;
                    reject_reality_transport(reality.as_ref(), "WebSocket", index)?;
                    if !validate_reality_transport(
                        reality.as_ref(),
                        certificate.as_deref(),
                        private_key.as_deref(),
                        false,
                        index,
                    )? {
                        websocket::validate_tls(
                            certificate.as_deref(),
                            private_key.as_deref(),
                            true,
                            index,
                        )?;
                    }
                    websocket.validate()?;
                }
                Inbound::TrojanWs {
                    users,
                    allow_insecure_transport,
                    websocket,
                    certificate,
                    private_key,
                    reality,
                    ..
                } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_users(users, false, index)?;
                    reject_reality_transport(reality.as_ref(), "WebSocket", index)?;
                    if !validate_reality_transport(
                        reality.as_ref(),
                        certificate.as_deref(),
                        private_key.as_deref(),
                        *allow_insecure_transport,
                        index,
                    )? {
                        websocket::validate_tls(
                            certificate.as_deref(),
                            private_key.as_deref(),
                            *allow_insecure_transport,
                            index,
                        )?;
                    }
                    websocket.validate()?;
                }
                Inbound::VlessGrpc {
                    users,
                    allow_insecure_transport,
                    grpc,
                    certificate,
                    private_key,
                    reality,
                    decryption,
                    ..
                } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_vless_users(users, index)?;
                    validate_vless_decryption(decryption.as_deref())?;
                    ensure!(
                        users.iter().all(|user| user.flow == VlessFlow::None),
                        "inbounds[{index}].users 的 gRPC VLESS flow 必须为空"
                    );
                    if !validate_reality_transport(
                        reality.as_ref(),
                        certificate.as_deref(),
                        private_key.as_deref(),
                        *allow_insecure_transport,
                        index,
                    )? {
                        grpc::validate_tls(
                            certificate.as_deref(),
                            private_key.as_deref(),
                            *allow_insecure_transport,
                            index,
                        )?;
                    }
                    grpc.validate(index)?;
                }
                Inbound::VmessGrpc {
                    users,
                    grpc,
                    certificate,
                    private_key,
                    reality,
                    ..
                } => {
                    vmess::validate_users(users, index)?;
                    // VMess 只信真实 TLS 或 REALITY；未配置 REALITY 时证书必填。
                    if !validate_reality_transport(
                        reality.as_ref(),
                        certificate.as_deref(),
                        private_key.as_deref(),
                        false,
                        index,
                    )? {
                        grpc::validate_tls(
                            certificate.as_deref(),
                            private_key.as_deref(),
                            false,
                            index,
                        )?;
                    }
                    grpc.validate(index)?;
                }
                Inbound::TrojanGrpc {
                    users,
                    allow_insecure_transport,
                    grpc,
                    certificate,
                    private_key,
                    reality,
                    ..
                } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_users(users, false, index)?;
                    if !validate_reality_transport(
                        reality.as_ref(),
                        certificate.as_deref(),
                        private_key.as_deref(),
                        *allow_insecure_transport,
                        index,
                    )? {
                        grpc::validate_tls(
                            certificate.as_deref(),
                            private_key.as_deref(),
                            *allow_insecure_transport,
                            index,
                        )?;
                    }
                    grpc.validate(index)?;
                }
                Inbound::VlessXhttp {
                    users,
                    allow_insecure_transport,
                    xhttp,
                    certificate,
                    private_key,
                    reality,
                    decryption,
                    ..
                } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_vless_users(users, index)?;
                    validate_vless_decryption(decryption.as_deref())?;
                    ensure!(
                        users.iter().all(|user| user.flow == VlessFlow::None),
                        "inbounds[{index}].users 的 XHTTP VLESS flow 必须为空"
                    );
                    let secured = validate_reality_transport(
                        reality.as_ref(),
                        certificate.as_deref(),
                        private_key.as_deref(),
                        *allow_insecure_transport,
                        index,
                    )?;
                    if secured {
                        ensure!(
                            !xhttp.h3,
                            "inbounds[{index}] REALITY 不支持 XHTTP/3（QUIC）"
                        );
                    } else {
                        xhttp::validate_tls(
                            certificate.as_deref(),
                            private_key.as_deref(),
                            *allow_insecure_transport,
                            index,
                        )?;
                    }
                    xhttp::validate_h3(xhttp.h3, certificate.as_deref(), index)?;
                    xhttp.validate(index)?;
                }
                Inbound::VmessXhttp {
                    users,
                    xhttp,
                    certificate,
                    private_key,
                    reality,
                    ..
                } => {
                    vmess::validate_users(users, index)?;
                    if !validate_reality_transport(
                        reality.as_ref(),
                        certificate.as_deref(),
                        private_key.as_deref(),
                        false,
                        index,
                    )? {
                        xhttp::validate_tls(
                            certificate.as_deref(),
                            private_key.as_deref(),
                            false,
                            index,
                        )?;
                    } else {
                        ensure!(
                            !xhttp.h3,
                            "inbounds[{index}] REALITY 不支持 XHTTP/3（QUIC）"
                        );
                    }
                    xhttp.validate(index)?;
                }
                Inbound::TrojanXhttp {
                    users,
                    allow_insecure_transport,
                    xhttp,
                    certificate,
                    private_key,
                    reality,
                    ..
                } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_users(users, false, index)?;
                    let secured = validate_reality_transport(
                        reality.as_ref(),
                        certificate.as_deref(),
                        private_key.as_deref(),
                        *allow_insecure_transport,
                        index,
                    )?;
                    if secured {
                        ensure!(
                            !xhttp.h3,
                            "inbounds[{index}] REALITY 不支持 XHTTP/3（QUIC）"
                        );
                    } else {
                        xhttp::validate_tls(
                            certificate.as_deref(),
                            private_key.as_deref(),
                            *allow_insecure_transport,
                            index,
                        )?;
                    }
                    xhttp::validate_h3(xhttp.h3, certificate.as_deref(), index)?;
                    xhttp.validate(index)?;
                }
                Inbound::VlessHttpUpgrade {
                    users,
                    allow_insecure_transport,
                    httpupgrade,
                    certificate,
                    private_key,
                    reality,
                    decryption,
                    ..
                } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_vless_users(users, index)?;
                    validate_vless_decryption(decryption.as_deref())?;
                    ensure!(
                        users.iter().all(|user| user.flow == VlessFlow::None),
                        "inbounds[{index}].users 的 HTTPUpgrade VLESS flow 必须为空"
                    );
                    reject_reality_transport(reality.as_ref(), "HTTPUpgrade", index)?;
                    if !validate_reality_transport(
                        reality.as_ref(),
                        certificate.as_deref(),
                        private_key.as_deref(),
                        *allow_insecure_transport,
                        index,
                    )? {
                        httpupgrade::validate_tls(
                            certificate.as_deref(),
                            private_key.as_deref(),
                            *allow_insecure_transport,
                            index,
                        )?;
                    }
                    httpupgrade.validate(index)?;
                }
                Inbound::VmessHttpUpgrade {
                    users,
                    httpupgrade,
                    certificate,
                    private_key,
                    reality,
                    ..
                } => {
                    vmess::validate_users(users, index)?;
                    reject_reality_transport(reality.as_ref(), "HTTPUpgrade", index)?;
                    if !validate_reality_transport(
                        reality.as_ref(),
                        certificate.as_deref(),
                        private_key.as_deref(),
                        false,
                        index,
                    )? {
                        httpupgrade::validate_tls(
                            certificate.as_deref(),
                            private_key.as_deref(),
                            false,
                            index,
                        )?;
                    }
                    httpupgrade.validate(index)?;
                }
                Inbound::TrojanHttpUpgrade {
                    users,
                    allow_insecure_transport,
                    httpupgrade,
                    certificate,
                    private_key,
                    reality,
                    ..
                } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_users(users, false, index)?;
                    reject_reality_transport(reality.as_ref(), "HTTPUpgrade", index)?;
                    if !validate_reality_transport(
                        reality.as_ref(),
                        certificate.as_deref(),
                        private_key.as_deref(),
                        *allow_insecure_transport,
                        index,
                    )? {
                        httpupgrade::validate_tls(
                            certificate.as_deref(),
                            private_key.as_deref(),
                            *allow_insecure_transport,
                            index,
                        )?;
                    }
                    httpupgrade.validate(index)?;
                }
                Inbound::VlessKcp {
                    users,
                    kcp,
                    certificate,
                    private_key,
                    decryption,
                    ..
                } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_vless_users(users, index)?;
                    validate_vless_decryption(decryption.as_deref())?;
                    ensure!(
                        users.iter().all(|user| user.flow == VlessFlow::None),
                        "inbounds[{index}].users 的 mKCP VLESS flow 必须为空"
                    );
                    kcp::validate_tls(certificate.as_deref(), private_key.as_deref(), index)?;
                    kcp.validate(index)?;
                }
                Inbound::VmessKcp {
                    users,
                    kcp,
                    certificate,
                    private_key,
                    ..
                } => {
                    vmess::validate_users(users, index)?;
                    kcp::validate_tls(certificate.as_deref(), private_key.as_deref(), index)?;
                    kcp.validate(index)?;
                }
                Inbound::TrojanKcp {
                    users,
                    kcp,
                    certificate,
                    private_key,
                    ..
                } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_users(users, false, index)?;
                    kcp::validate_tls(certificate.as_deref(), private_key.as_deref(), index)?;
                    kcp.validate(index)?;
                }
                Inbound::VlessHttp {
                    users,
                    allow_insecure_transport,
                    http,
                    certificate,
                    private_key,
                    decryption,
                    ..
                } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_vless_users(users, index)?;
                    validate_vless_decryption(decryption.as_deref())?;
                    ensure!(
                        users.iter().all(|user| user.flow == VlessFlow::None),
                        "inbounds[{index}].users 的 HTTP VLESS flow 必须为空"
                    );
                    websocket::validate_tls(
                        certificate.as_deref(),
                        private_key.as_deref(),
                        *allow_insecure_transport,
                        index,
                    )?;
                    http.validate(index)?;
                }
                Inbound::VmessHttp {
                    users,
                    http,
                    certificate,
                    private_key,
                    ..
                } => {
                    vmess::validate_users(users, index)?;
                    websocket::validate_tls(
                        certificate.as_deref(),
                        private_key.as_deref(),
                        true,
                        index,
                    )?;
                    http.validate(index)?;
                }
                Inbound::TrojanHttp {
                    users,
                    allow_insecure_transport,
                    http,
                    certificate,
                    private_key,
                    ..
                } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_users(users, false, index)?;
                    websocket::validate_tls(
                        certificate.as_deref(),
                        private_key.as_deref(),
                        *allow_insecure_transport,
                        index,
                    )?;
                    http.validate(index)?;
                }
                Inbound::VlessQuic {
                    users,
                    quic,
                    decryption,
                    ..
                } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_vless_users(users, index)?;
                    validate_vless_decryption(decryption.as_deref())?;
                    ensure!(
                        users.iter().all(|user| user.flow == VlessFlow::None),
                        "inbounds[{index}].users 的 QUIC VLESS flow 必须为空"
                    );
                    quic.validate(index)?;
                }
                Inbound::VmessQuic { users, quic, .. } => {
                    vmess::validate_users(users, index)?;
                    quic.validate(index)?;
                }
                Inbound::TrojanQuic { users, quic, .. } => {
                    websocket::validate_user_count(users.len(), index)?;
                    validate_users(users, false, index)?;
                    quic.validate(index)?;
                }
                Inbound::DokodemoDoor {
                    address,
                    port,
                    network,
                    sniffing,
                    ..
                } => {
                    DokodemoDoor {
                        address: address.clone(),
                        port: *port,
                        network: network.clone(),
                        sniffing: sniffing.clone(),
                    }
                    .validate(index)?;
                }
                Inbound::Wireguard {
                    private_key,
                    address,
                    peers,
                    mtu,
                    max_peers,
                    max_tcp_connections,
                    max_udp_associations,
                    max_queued_datagrams,
                    max_handshake_inits_per_sec,
                    peer_idle_timeout_secs,
                    ..
                } => {
                    validate_wireguard_server(
                        index,
                        private_key,
                        address,
                        peers,
                        *mtu,
                        *max_peers,
                        *max_tcp_connections,
                        *max_udp_associations,
                        *max_queued_datagrams,
                        *max_handshake_inits_per_sec,
                        *peer_idle_timeout_secs,
                    )?;
                }
                Inbound::Snell {
                    psk,
                    version,
                    users,
                    obfs_mode,
                    mode,
                    ..
                } => {
                    ensure!(
                        matches!(version, 4..=6),
                        "inbounds[{index}].version 仅支持 4、5 或 6"
                    );
                    if *version == 6 {
                        ensure!(
                            (12..=255).contains(&psk.0.len()),
                            "inbounds[{index}].psk 长度必须在12到255字节之间（v6）"
                        );
                        ensure!(
                            mode.as_deref().is_none_or(|mode| matches!(
                                mode,
                                "default" | "unshaped" | "unsafe-raw"
                            )),
                            "inbounds[{index}].mode 在 v6 下仅支持 default、unshaped 或 unsafe-raw"
                        );
                    } else {
                        ensure!(
                            (1..=4096).contains(&psk.0.len()),
                            "inbounds[{index}].psk 长度必须在1到4096字节之间"
                        );
                        ensure!(mode.is_none(), "inbounds[{index}].mode 仅适用于 v6");
                    }
                    ensure!(
                        users.len() <= 1024,
                        "inbounds[{index}].users 数量不得超过1024"
                    );
                    crate::transport::snell_obfs::validate(
                        *version,
                        obfs_mode.as_deref(),
                        None,
                        None,
                    )
                    .map_err(|_| {
                        anyhow!("inbounds[{index}].obfs_mode无效，v4/v5可用none/http/tls，v6仅none")
                    })?;
                    let mut userkeys = HashSet::new();
                    for (user_index, user) in users.iter().enumerate() {
                        ensure!(
                            (1..=255).contains(&user.userkey.0.len()),
                            "inbounds[{index}].users[{user_index}].userkey 长度必须在1到255字节之间"
                        );
                        ensure!(
                            userkeys.insert(user.userkey.0.as_str()),
                            "inbounds[{index}].users[{user_index}].userkey 重复"
                        );
                    }
                }
                Inbound::Hysteria2 {
                    users,
                    obfs,
                    masquerade,
                    up_mbps,
                    down_mbps,
                    ..
                } => {
                    for (name, value) in [("up_mbps", up_mbps), ("down_mbps", down_mbps)] {
                        if let Some(mbps) = value {
                            let bps = mbps.checked_mul(1_000_000).ok_or_else(|| {
                                anyhow::anyhow!("inbounds[{index}].{name} 超出可表示范围")
                            })?;
                            ensure!(
                                bps == 0 || bps >= 524_288,
                                "inbounds[{index}].{name} 必须为0或至少0.524288 Mbps"
                            );
                        }
                    }
                    ensure!(!users.is_empty(), "inbounds[{index}].users 不得为空");
                    validate_users(users, false, index)?;
                    if let Some(obfs) = obfs {
                        ensure!(
                            !obfs.password.0.is_empty(),
                            "inbounds[{index}].obfs.password 不得为空"
                        );
                        match obfs.kind {
                            Hysteria2ObfsType::Salamander => ensure!(
                                obfs.min_packet_size.is_none() && obfs.max_packet_size.is_none(),
                                "inbounds[{index}].obfs 的 min/max_packet_size 仅适用于 gecko"
                            ),
                            Hysteria2ObfsType::Gecko => {
                                // 对齐官方 `WrapPacketConnGecko`：仅要求
                                // min > 0、min <= max、max <= 2048。
                                let min = obfs.min_packet_size.unwrap_or(512);
                                let max = obfs.max_packet_size.unwrap_or(1200);
                                ensure!(
                                    min > 0 && min <= max && max <= 2048,
                                    "inbounds[{index}].obfs 的 gecko 分片长度必须满足 min>0、min<=max、max<=2048"
                                );
                            }
                        }
                    }
                    if let Some(masquerade) = masquerade {
                        match masquerade.kind {
                            Hysteria2MasqueradeType::String => {
                                ensure!(
                                    masquerade.content.is_some() && masquerade.directory.is_none(),
                                    "inbounds[{index}].masquerade 的 string 类型只接受 content"
                                );
                                ensure!(
                                    masquerade
                                        .status_code
                                        .is_none_or(|status| (100..=599).contains(&status)),
                                    "inbounds[{index}].masquerade.status_code 必须在 100-599 之间"
                                );
                            }
                            Hysteria2MasqueradeType::File => {
                                ensure!(
                                    masquerade.directory.is_some()
                                        && masquerade.content.is_none()
                                        && masquerade.status_code.is_none(),
                                    "inbounds[{index}].masquerade 的 file 类型只接受 directory"
                                );
                                let directory = masquerade.directory.as_deref().unwrap_or("");
                                ensure!(
                                    !directory.is_empty() && directory.is_ascii(),
                                    "inbounds[{index}].masquerade.directory 必须是非空 ASCII 路径"
                                );
                            }
                        }
                    }
                }
                Inbound::Tuic {
                    users,
                    alpn,
                    max_streams,
                    congestion_control,
                    ..
                } => {
                    if let Some(value) = congestion_control {
                        crate::transport::tuic::modern::CongestionControl::parse(value).map_err(
                            |_| {
                                anyhow::anyhow!(
                                    "inbounds[{index}].congestion_control 仅支持 cubic/new_reno/bbr"
                                )
                            },
                        )?;
                    }
                    ensure!(!users.is_empty(), "inbounds[{index}].users 不得为空");
                    ensure!(
                        users.len() <= 1024,
                        "inbounds[{index}].users 数量不得超过1024"
                    );
                    ensure!(
                        alpn.iter()
                            .all(|value| !value.is_empty() && value.len() <= 255),
                        "inbounds[{index}].alpn 无效"
                    );
                    ensure!(
                        *max_streams != Some(0),
                        "inbounds[{index}].max_streams 不得为 0"
                    );
                    let mut uuids = HashSet::new();
                    for (user_index, user) in users.iter().enumerate() {
                        ensure!(
                            parse_uuid(&user.uuid).is_some(),
                            "inbounds[{index}].users[{user_index}].uuid 无效"
                        );
                        ensure!(
                            (1..=4096).contains(&user.password.0.len()),
                            "inbounds[{index}].users[{user_index}].password 长度必须在1到4096字节之间"
                        );
                        ensure!(
                            uuids.insert(user.uuid.to_ascii_lowercase()),
                            "inbounds[{index}].users[{user_index}].uuid 重复"
                        );
                    }
                }
                Inbound::ShadowTls {
                    version,
                    users,
                    handshake,
                    handshake_for_server_name,
                    detour,
                    ..
                } => {
                    handshake.target()?;
                    for (server_name, target) in handshake_for_server_name {
                        ensure!(
                            !server_name.is_empty()
                                && server_name.len() <= 253
                                && server_name.is_ascii()
                                && !server_name
                                    .chars()
                                    .any(|ch| ch.is_ascii_whitespace() || ch == '\0'),
                            "inbounds[{index}].handshake_for_server_name 的域名无效"
                        );
                        target.target()?;
                    }
                    ensure!(
                        *version == 3,
                        "inbounds[{index}].version 仅支持 ShadowTLS v3"
                    );
                    ensure!(!users.is_empty(), "inbounds[{index}].users 不得为空");
                    ensure!(
                        users.len() <= 1024,
                        "inbounds[{index}].users 数量不得超过1024"
                    );
                    // 上游允许多个用户名共享同一密码；这里只要求名称唯一且非空。
                    let mut names = HashSet::new();
                    for (user_index, user) in users.iter().enumerate() {
                        ensure!(
                            !user.name.is_empty() && !user.password.is_empty(),
                            "inbounds[{index}].users[{user_index}] 用户名和密码不得为空"
                        );
                        ensure!(
                            (1..=4096).contains(&user.password.len()),
                            "inbounds[{index}].users[{user_index}].password 长度必须在1到4096字节之间"
                        );
                        ensure!(
                            names.insert(user.name.as_str()),
                            "inbounds[{index}].users[{user_index}].用户名重复"
                        );
                    }
                    handshake.target()?;
                    ensure!(!detour.is_empty(), "inbounds[{index}].detour 不得为空");
                }
                Inbound::Nw3 {
                    listen,
                    key,
                    out,
                    dial,
                    dial4,
                    dial6,
                    certificate,
                    private_key,
                    ..
                } => {
                    ensure!(
                        key.len() == 32
                            && key
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
                        "inbounds[{index}].key 必须是32个小写十六进制字符"
                    );
                    ensure!(listen.port() != 0, "inbounds[{index}].listen 端口不得为0");
                    ensure!(
                        certificate.is_some() == private_key.is_some(),
                        "inbounds[{index}].certificate 和 private_key 必须成对配置"
                    );
                    let dials = [dial.is_some(), dial4.is_some(), dial6.is_some()];
                    ensure!(
                        dials.iter().filter(|present| **present).count() <= 1,
                        "inbounds[{index}].dial、dial4、dial6 互斥"
                    );
                    ensure!(
                        !matches!(out, Nw3Out::Egress) || dials.iter().all(|present| !*present),
                        "inbounds[{index}].out=egress 与 dial、dial4、dial6 互斥"
                    );
                    for (name, value) in [("dial", dial), ("dial4", dial4), ("dial6", dial6)] {
                        if let Some(value) = value {
                            ensure!(
                                !value.is_empty()
                                    && value.is_ascii()
                                    && !value.chars().any(char::is_whitespace),
                                "inbounds[{index}].{name} 必须是非空 ASCII 且不含空白"
                            );
                        }
                    }
                }
            }
            if let Some((certificate, private_key)) = inbound.tls_paths() {
                ensure!(
                    !certificate.as_os_str().is_empty(),
                    "inbounds[{index}].certificate 不得为空"
                );
                ensure!(
                    !private_key.as_os_str().is_empty(),
                    "inbounds[{index}].private_key 不得为空"
                );
            }
        }
        if let Some(egress) = &self.nw3_egress {
            validate_nw3_egress(egress)?;
        }
        // ShadowTLS 认证后的明文流只能交给同配置内的明文 TCP 入站。
        for (index, inbound) in self.inbounds.iter().enumerate() {
            let Inbound::ShadowTls { detour, .. } = inbound else {
                continue;
            };
            let target = self
                .inbounds
                .iter()
                .find(|candidate| candidate.tag() == detour)
                .ok_or_else(|| anyhow::anyhow!("inbounds[{index}].detour 引用了不存在的入口"))?;
            ensure!(
                target.tag() != inbound.tag(),
                "inbounds[{index}].detour 不得指向自身"
            );
            ensure!(
                shadowtls_detour_allowed(target),
                "inbounds[{index}].detour 目标必须是明文 TCP 入站（shadowsocks/snell/socks5/http/mixed/无TLS的vmess）"
            );
        }

        // 监听地址冲突：两个入口抢占同一 (地址, 端口, 网络类型) 时行为不可靠。
        //
        // 两种情况都要拦：
        // - 地址完全相同 → `run` 报 `AddrInUse` 并整体退出；
        // - 一个是未指定地址（`0.0.0.0` / `::`）而另一个落在其覆盖范围内 →
        //   macOS 上靠 SO_REUSEADDR 能同时绑定成功，但连接由哪个套接字接收
        //   不确定（实测两个入口都 ready），Linux 上直接 EADDRINUSE。
        //   两种结果都不能接受，且都不是「按协议分流」。
        //
        // TCP 与 UDP 互不冲突（Hysteria2 等只占 UDP）。
        for (index, inbound) in self.inbounds.iter().enumerate() {
            let (tcp, udp) = inbound.networks();
            let address = inbound.listen();
            for earlier in self.inbounds.iter().take(index) {
                // 端口 0 由内核分配实际端口，两个入口会各得一个，不构成冲突。
                if address.port() == 0
                    || earlier.listen().port() != address.port()
                    || !overlapping(earlier.listen().ip(), address.ip())
                {
                    continue;
                }
                let (earlier_tcp, earlier_udp) = earlier.networks();
                let tcp_clash = tcp && earlier_tcp;
                let udp_clash = udp && earlier_udp;
                let same_ip = earlier.listen().ip() == address.ip();
                ensure!(
                    !tcp_clash && !udp_clash,
                    "inbounds[{index}]（{}，监听 {}）与更早的 {}（监听 {}）在端口 {} 上冲突\
                     （{}）：{}。每个 (地址, 端口, TCP/UDP) 只能由一个入口占用；\
                     需要单端口承载多协议时，用 `mixed`（SOCKS5/HTTP）或前一个入口的 `fallbacks` 回放",
                    inbound.tag(),
                    address,
                    earlier.tag(),
                    earlier.listen(),
                    address.port(),
                    match (tcp_clash, udp_clash) {
                        (true, true) => "TCP 与 UDP 均冲突",
                        (true, false) => "TCP 冲突",
                        (false, true) => "UDP 冲突",
                        (false, false) => unreachable!(),
                    },
                    if same_ip {
                        "地址相同"
                    } else {
                        "其中一个监听未指定地址（0.0.0.0 / ::），覆盖另一个"
                    }
                );
            }
        }

        // 单 IP 上限超过全局上限没有意义（永远不会先撞到它），但不该因此
        // 拒绝配置：`max_handshakes` 调小时，默认的 `per_ip_handshakes=8`
        // 会自然大于它。运行期会取两者较小值，这里只提示不报错。

        if let Some(sniffing) = &self.sniffing {
            ensure!(
                (10..=10_000).contains(&sniffing.timeout_ms),
                "sniffing.timeout_ms 必须在 10-10000 之间"
            );
            let mut seen = HashSet::new();
            for kind in &sniffing.dest_override {
                ensure!(seen.insert(*kind), "sniffing.dest_override 不得重复");
            }
            for tag in &sniffing.inbounds {
                ensure!(
                    inbound_tags.contains(tag.as_str()),
                    "sniffing.inbounds 引用了不存在的入口"
                );
            }
            if !sniffing.enabled {
                ensure!(
                    sniffing.dest_override.is_empty()
                        && sniffing.inbounds.is_empty()
                        && !sniffing.route_only,
                    "sniffing 禁用时不得配置 inbounds/dest_override/route_only"
                );
            }
        }

        let mut outbound_tags = HashSet::new();
        for (index, outbound) in self.outbounds.iter().enumerate() {
            ensure!(valid_tag(&outbound.tag), "outbounds[{index}].tag 格式无效");
            ensure!(
                outbound_tags.insert(outbound.tag.as_str()),
                "outbounds[{index}].tag 重复"
            );
            if outbound.kind.is_proxy() {
                if outbound.kind != OutboundKind::Nw3Vector {
                    let endpoint = outbound
                        .endpoint
                        .as_deref()
                        .ok_or_else(|| anyhow!("outbounds[{index}].endpoint 不得为空"))?;
                    // 未加方括号时只允许一个冒号；否则 `::1:1080` 会被误当成域名。
                    let ambiguous_ipv6 =
                        !endpoint.starts_with('[') && endpoint.matches(':').count() > 1;
                    ensure!(
                        !ambiguous_ipv6 && crate::session::parse_endpoint(endpoint).is_some(),
                        "outbounds[{index}].endpoint 必须是 HOST:PORT 或 [IPv6]:PORT"
                    );
                }
                match outbound.kind {
                    OutboundKind::Socks5 | OutboundKind::Http => ensure!(
                        outbound.username.is_some() == outbound.password.is_some(),
                        "outbounds[{index}].username 和 password 必须成对配置"
                    ),
                    OutboundKind::Trojan => {
                        ensure!(
                            outbound.password.is_some() && outbound.username.is_none(),
                            "trojan 出站必须只配置 password"
                        );
                        ensure!(
                            outbound.tls.is_some() || outbound.reality.is_some(),
                            "trojan 出站必须配置 tls（含 ca_file）或 reality"
                        );
                    }
                    OutboundKind::Vless => {
                        ensure!(
                            outbound.uuid.is_some()
                                && outbound.username.is_none()
                                && outbound.password.is_none(),
                            "vless 出站必须配置 uuid，且不得配置 username/password"
                        );
                        if let Some(encryption) = &outbound.encryption {
                            crate::config::vless_encryption::parse_client(encryption)?;
                        }
                        if outbound.flow == Some(VlessFlow::Vision) {
                            ensure!(
                                outbound.tls.is_some() || outbound.reality.is_some(),
                                "xtls-rprx-vision 出站必须配置 tls（含 ca_file）或 reality"
                            );
                            ensure!(
                                outbound.transport.is_none(),
                                "xtls-rprx-vision 出站不支持 ws/grpc/httpupgrade 传输"
                            );
                        }
                    }
                    OutboundKind::Vmess => {
                        ensure!(
                            outbound.uuid.is_some()
                                && outbound.username.is_none()
                                && outbound.password.is_none(),
                            "vmess 出站必须配置 uuid，且不得配置 username/password"
                        );
                        ensure!(
                            matches!(outbound.security, None | Some(3) | Some(4)),
                            "vmess 出站 security 只支持 3 或 4"
                        );
                    }
                    OutboundKind::Naive => {
                        let options = outbound
                            .naive
                            .as_ref()
                            .ok_or_else(|| anyhow!("Naive出站需要naive参数"))?;
                        options.validate()?;
                        ensure!(
                            outbound.username.is_some()
                                && outbound.password.is_some()
                                && outbound.tls.is_some(),
                            "Naive出站需要username/password与TLS信任锚"
                        );
                        ensure!(
                            !outbound
                                .username
                                .as_deref()
                                .is_some_and(|name| name.contains(':')),
                            "Naive Basic用户名不得含冒号"
                        );
                        ensure!(
                            options.http_version != NaiveHttpVersion::H3 || outbound.via.is_none(),
                            "Naive H3不能嵌入TCP via链"
                        );
                    }
                    OutboundKind::ShadowTls => {
                        let password = outbound
                            .password
                            .as_deref()
                            .ok_or_else(|| anyhow!("shadowtls 出站必须配置 password"))?;
                        ensure!(
                            (1..=4096).contains(&password.len()),
                            "shadowtls 出站 password 长度必须在1到4096字节之间"
                        );
                        ensure!(
                            outbound.username.is_none(),
                            "shadowtls 出站不得配置 username"
                        );
                        let tls = outbound
                            .tls
                            .as_ref()
                            .ok_or_else(|| anyhow!("shadowtls 出站必须配置 tls（含 ca_file）"))?;
                        ensure!(
                            !tls.ca_file.is_empty(),
                            "outbounds[{index}].tls.ca_file 必须是非空 ASCII 路径且不含控制字符"
                        );
                        let server_name = tls
                            .server_name
                            .as_deref()
                            .ok_or_else(|| anyhow!("shadowtls 出站必须配置 tls.server_name"))?;
                        ensure!(
                            matches!(
                                crate::session::Host::parse(server_name),
                                Some(crate::session::Host::Domain(_))
                            ),
                            "outbounds[{index}].tls.server_name 必须是 DNS 名"
                        );
                        ensure!(
                            outbound.reality.is_none()
                                && outbound.uuid.is_none()
                                && outbound.flow.is_none()
                                && outbound.encryption.is_none()
                                && outbound.method.is_none()
                                && outbound.security.is_none()
                                && outbound.transport.is_none()
                                && !outbound.udp_over_tcp
                                && outbound.domain.is_none()
                                && outbound.wireguard.is_none()
                                && outbound.hysteria2.is_none()
                                && outbound.tuic.is_none()
                                && outbound.snell.is_none()
                                && outbound.naive.is_none()
                                && outbound.anytls.is_none()
                                && outbound.url.is_none()
                                && outbound.outbounds.is_empty()
                                && outbound.default.is_none()
                                && outbound.probe.is_none()
                                && outbound.interval_ms.is_none()
                                && outbound.tolerance_ms.is_none()
                                && outbound.probe_timeout_ms.is_none(),
                            "shadowtls 出站不支持 reality/uuid/flow/encryption/method/security/transport/udp_over_tcp/domain/wireguard/hysteria2/tuic/snell/naive/anytls/url/outbounds/default/probe/interval_ms/tolerance_ms/probe_timeout_ms"
                        );
                    }
                    OutboundKind::Snell => {
                        outbound
                            .snell
                            .as_ref()
                            .ok_or_else(|| anyhow!("Snell出站缺少snell参数"))?
                            .validate()?;
                        ensure!(
                            outbound.username.is_none()
                                && outbound.password.is_none()
                                && outbound.tls.is_none(),
                            "Snell出站只使用snell身份与记录承载，不支持username/password/tls"
                        );
                    }
                    OutboundKind::Shadowsocks => {
                        ensure!(
                            outbound.password.is_some() && outbound.username.is_none(),
                            "shadowsocks 出站必须只配置 password"
                        );
                        ensure!(outbound.method.is_some(), "shadowsocks 出站必须配置 method");
                        ensure!(outbound.tls.is_none(), "shadowsocks 出站不支持 tls");
                    }
                    OutboundKind::Hysteria2 => {
                        ensure!(
                            outbound.password.is_some() && outbound.username.is_none(),
                            "hysteria2 出站必须只配置 password"
                        );
                        ensure!(
                            outbound.tls.is_some(),
                            "hysteria2 出站必须配置 tls（含 ca_file）"
                        );
                        ensure!(
                            outbound.uuid.is_none()
                                && outbound.method.is_none()
                                && outbound.security.is_none()
                                && outbound.transport.is_none()
                                && outbound.encryption.is_none()
                                && outbound.via.is_none(),
                            "hysteria2 出站不得配置 uuid/method/security/transport/encryption/via"
                        );
                        if let Some(options) = &outbound.hysteria2 {
                            for (name, value) in [
                                ("up_mbps", options.up_mbps),
                                ("down_mbps", options.down_mbps),
                            ] {
                                if let Some(mbps) = value {
                                    let bps = mbps.checked_mul(1_000_000).ok_or_else(|| {
                                        anyhow!(
                                            "outbounds[{index}].hysteria2.{name} 超出可表示范围"
                                        )
                                    })?;
                                    ensure!(
                                        bps == 0 || bps >= 524_288,
                                        "outbounds[{index}].hysteria2.{name} 必须为0或至少0.524288 Mbps"
                                    );
                                }
                            }
                            if let Some(obfs) = &options.obfs {
                                ensure!(
                                    !obfs.password.0.is_empty() && obfs.password.0.len() <= 4096,
                                    "outbounds[{index}].hysteria2.obfs.password 长度无效"
                                );
                                match obfs.kind {
                                    Hysteria2ObfsType::Salamander => ensure!(
                                        obfs.min_packet_size.is_none()
                                            && obfs.max_packet_size.is_none(),
                                        "outbounds[{index}].hysteria2.obfs 的 gecko 字段仅适用于 gecko"
                                    ),
                                    Hysteria2ObfsType::Gecko => {
                                        // 对齐官方 `WrapPacketConnGecko` 的约束。
                                        let min = obfs.min_packet_size.unwrap_or(512);
                                        let max = obfs.max_packet_size.unwrap_or(1200);
                                        ensure!(
                                            min > 0 && min <= max && max <= 2048,
                                            "outbounds[{index}].hysteria2.obfs gecko 分片长度必须满足 min>0、min<=max、max<=2048"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    OutboundKind::Tuic => {
                        ensure!(
                            outbound.uuid.is_some()
                                && outbound.password.is_some()
                                && outbound.username.is_none(),
                            "tuic 出站必须配置 uuid 与 password"
                        );
                        ensure!(outbound.tls.is_some(), "tuic 出站必须配置 tls");
                        if let Some(algorithm) = outbound
                            .tuic
                            .as_ref()
                            .and_then(|options| options.congestion_control.as_deref())
                        {
                            crate::transport::tuic::modern::CongestionControl::parse(algorithm)
                                .map_err(|_| anyhow!("outbounds[{index}].tuic.congestion_control 仅支持cubic/new_reno/bbr"))?;
                        }
                        if let Some(uuid) = &outbound.uuid {
                            ensure!(
                                parse_uuid(uuid).is_some(),
                                "outbounds[{index}].uuid 必须是标准 UUID"
                            );
                        }
                        ensure!(
                            outbound.method.is_none()
                                && outbound.security.is_none()
                                && outbound.transport.is_none()
                                && outbound.encryption.is_none()
                                && outbound.via.is_none(),
                            "tuic 出站不得配置 method/security/transport/encryption/via"
                        );
                    }
                    OutboundKind::Nw3Vector => {
                        let raw = outbound
                            .url
                            .as_deref()
                            .ok_or_else(|| anyhow!("nw3-vector 出站必须配置 url"))?;
                        let parsed = url::Url::parse(raw)
                            .map_err(|_| anyhow!("outbounds[{index}].url 不是合法 URL"))?;
                        ensure!(
                            parsed.scheme() == "vector",
                            "outbounds[{index}].url 必须是 vector:// URL"
                        );
                        ensure!(
                            outbound.username.is_none()
                                && outbound.password.is_none()
                                && outbound.uuid.is_none()
                                && outbound.method.is_none()
                                && outbound.security.is_none()
                                && outbound.transport.is_none()
                                && outbound.tls.is_none()
                                && outbound.via.is_none()
                                && outbound.encryption.is_none(),
                            "nw3-vector 出站不得配置 endpoint 之外的代理字段"
                        );
                    }
                    OutboundKind::Anytls => {
                        outbound.anytls.clone().unwrap_or_default().validate()?;
                        ensure!(
                            outbound.password.is_some() && outbound.username.is_none(),
                            "anytls 出站必须只配置 password"
                        );
                        ensure!(
                            outbound.tls.is_some(),
                            "anytls 出站必须配置 tls（含 ca_file）"
                        );
                        ensure!(
                            outbound.uuid.is_none()
                                && outbound.method.is_none()
                                && outbound.security.is_none()
                                && outbound.transport.is_none()
                                && outbound.encryption.is_none(),
                            "anytls 出站不得配置 uuid/method/security/transport/encryption"
                        );
                    }
                    OutboundKind::Wireguard => {
                        ensure!(
                            outbound.username.is_none()
                                && outbound.password.is_none()
                                && outbound.uuid.is_none()
                                && outbound.method.is_none()
                                && outbound.security.is_none()
                                && outbound.transport.is_none()
                                && outbound.tls.is_none()
                                && outbound.via.is_none(),
                            "wireguard 出站不得配置 username/password/uuid/method/security/transport/tls/via"
                        );
                        let wireguard = outbound
                            .wireguard
                            .as_ref()
                            .ok_or_else(|| anyhow!("wireguard 出站必须配置 wireguard"))?;
                        ensure!(
                            parse_wireguard_key(&wireguard.private_key).is_some(),
                            "outbounds[{index}].wireguard.private_key 必须是 32 字节 base64"
                        );
                        ensure!(
                            parse_wireguard_key(&wireguard.peer_public_key).is_some(),
                            "outbounds[{index}].wireguard.peer_public_key 必须是 32 字节 base64"
                        );
                        if let Some(key) = &wireguard.preshared_key {
                            ensure!(
                                parse_wireguard_key(key).is_some(),
                                "outbounds[{index}].wireguard.preshared_key 必须是 32 字节 base64"
                            );
                        }
                        ensure!(
                            !wireguard.address.is_empty()
                                && wireguard.address.len() <= smoltcp::config::IFACE_MAX_ADDR_COUNT,
                            "outbounds[{index}].wireguard.address 数量超过当前用户态接口容量"
                        );
                        for address in &wireguard.address {
                            ensure!(
                                address.parse::<IpNet>().is_ok(),
                                "outbounds[{index}].wireguard.address 必须是 CIDR"
                            );
                        }
                        if let Some(mtu) = wireguard.mtu {
                            ensure!(
                                (576..=1500).contains(&mtu),
                                "outbounds[{index}].wireguard.mtu 必须在 576-1500 之间"
                            );
                        }
                    }
                    _ => {}
                }
                if !matches!(
                    outbound.kind,
                    OutboundKind::Vless | OutboundKind::Vmess | OutboundKind::Tuic
                ) {
                    ensure!(
                        outbound.uuid.is_none(),
                        "outbounds[{index}].uuid 仅适用于 vless/vmess/tuic"
                    );
                } else if let Some(uuid) = &outbound.uuid {
                    ensure!(
                        parse_uuid(uuid).is_some(),
                        "outbounds[{index}].uuid 必须是标准 UUID"
                    );
                }
                if outbound.kind != OutboundKind::Shadowsocks {
                    ensure!(
                        outbound.method.is_none(),
                        "outbounds[{index}].method 仅适用于 shadowsocks"
                    );
                }
                ensure!(
                    outbound.kind == OutboundKind::Vless || outbound.encryption.is_none(),
                    "outbounds[{index}].encryption 仅适用于 vless"
                );
                ensure!(
                    outbound.kind == OutboundKind::Hysteria2 || outbound.hysteria2.is_none(),
                    "outbounds[{index}].hysteria2 仅适用于 hysteria2"
                );
                ensure!(
                    outbound.kind == OutboundKind::Anytls || outbound.anytls.is_none(),
                    "outbounds[{index}].anytls仅适用于AnyTLS"
                );
                ensure!(
                    outbound.kind == OutboundKind::Naive || outbound.naive.is_none(),
                    "outbounds[{index}].naive仅适用于Naive"
                );
                ensure!(
                    outbound.kind == OutboundKind::Snell || outbound.snell.is_none(),
                    "outbounds[{index}].snell 仅适用于snell"
                );
                ensure!(
                    outbound.kind == OutboundKind::Tuic || outbound.tuic.is_none(),
                    "outbounds[{index}].tuic 仅适用于 tuic"
                );
                ensure!(
                    outbound.kind == OutboundKind::Nw3Vector || outbound.url.is_none(),
                    "outbounds[{index}].url 仅适用于 nw3-vector"
                );
                ensure!(
                    outbound.kind == OutboundKind::Vless || outbound.flow.is_none(),
                    "outbounds[{index}].flow 仅适用于 vless"
                );
                ensure!(
                    outbound.kind == OutboundKind::Shadowsocks || !outbound.udp_over_tcp,
                    "outbounds[{index}].udp_over_tcp 仅适用于 shadowsocks"
                );
                if outbound.kind != OutboundKind::Vmess {
                    ensure!(
                        outbound.security.is_none(),
                        "outbounds[{index}].security 仅适用于 vmess"
                    );
                }
                ensure!(
                    outbound.domain.is_none(),
                    "outbounds[{index}].domain 仅适用于 reverse"
                );
                ensure!(
                    outbound.kind == OutboundKind::Wireguard || outbound.wireguard.is_none(),
                    "outbounds[{index}].wireguard 仅适用于 wireguard"
                );
                if let Some(transport) = &outbound.transport {
                    ensure!(
                        matches!(
                            outbound.kind,
                            OutboundKind::Vless | OutboundKind::Vmess | OutboundKind::Trojan
                        ),
                        "outbounds[{index}].transport 仅适用于 vless/vmess/trojan"
                    );
                    transport
                        .validate(outbound.tls.is_some() || outbound.reality.is_some(), index)?;
                    ensure!(
                        outbound.via.is_none() || !transport.uses_udp_socket(),
                        "outbounds[{index}] UDP 底层承载不能嵌入仅提供 TCP 的 via"
                    );
                    ensure!(
                        outbound.reality.is_none() || !transport.uses_udp_socket(),
                        "outbounds[{index}] REALITY 不能与 QUIC/UDP 底层承载组合"
                    );
                }
                if let Some(reality) = &outbound.reality {
                    ensure!(
                        matches!(
                            outbound.kind,
                            OutboundKind::Vless | OutboundKind::Vmess | OutboundKind::Trojan
                        ),
                        "outbounds[{index}].reality 仅适用于 vless/vmess/trojan"
                    );
                    ensure!(
                        outbound.tls.is_none(),
                        "outbounds[{index}].reality 不能与 tls 同时配置"
                    );
                    ensure!(
                        outbound.transport.as_ref().is_none_or(|transport| matches!(
                            transport.kind,
                            OutboundTransportType::Grpc | OutboundTransportType::Xhttp
                        )),
                        "outbounds[{index}] REALITY 仅支持 RAW、XHTTP、gRPC 传输"
                    );
                    let key = base64::engine::general_purpose::STANDARD
                        .decode(&reality.public_key)
                        .or_else(|_| {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(&reality.public_key)
                        })
                        .ok();
                    ensure!(
                        key.is_some_and(|key| key.len() == 32),
                        "outbounds[{index}].reality.public_key 必须是 32 字节 base64"
                    );
                    ensure!(
                        reality.short_id.len() <= 16
                            && reality.short_id.len().is_multiple_of(2)
                            && reality
                                .short_id
                                .bytes()
                                .all(|byte| byte.is_ascii_hexdigit()),
                        "outbounds[{index}].reality.short_id 必须是最多16个十六进制字符"
                    );
                    ensure!(
                        !reality.server_name.is_empty()
                            && reality.server_name.len() <= 253
                            && reality.server_name.is_ascii()
                            && reality.server_name.parse::<std::net::IpAddr>().is_err()
                            && !reality.server_name.chars().any(char::is_whitespace),
                        "outbounds[{index}].reality.server_name 必须是 DNS 名"
                    );
                    if let Some(version) = &reality.version {
                        let parts: Vec<_> = version.split('.').collect();
                        ensure!(
                            parts.len() == 3
                                && parts.iter().all(|part| {
                                    !part.is_empty()
                                        && part.len() <= 3
                                        && part.parse::<u8>().is_ok()
                                }),
                            "outbounds[{index}].reality.version 必须是三段十进制版本"
                        );
                    }
                    if let Some(value) = &reality.mldsa65_verify {
                        let decoded = base64::engine::general_purpose::STANDARD
                            .decode(value)
                            .or_else(|_| {
                                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value)
                            })
                            .map_err(|_| {
                                anyhow::anyhow!(
                                    "outbounds[{index}].reality.mldsa65Verify 必须是 base64"
                                )
                            })?;
                        ensure!(
                            decoded.len() == 1952,
                            "outbounds[{index}].reality.mldsa65Verify 必须是1952字节 ML-DSA-65 公钥"
                        );
                    }
                }
                // ShadowTLS password 允许 1..=4096 字节，已在协议分支单独校验。
                if outbound.kind != OutboundKind::ShadowTls {
                    for (name, value) in [
                        ("username", outbound.username.as_deref()),
                        ("password", outbound.password.as_deref()),
                    ] {
                        if let Some(value) = value {
                            ensure!(
                                !value.is_empty()
                                    && value.len() <= 255
                                    && !value
                                        .chars()
                                        .any(|ch| ch == '\0' || ch == '\r' || ch == '\n'),
                                "outbounds[{index}].{name} 必须非空、不超过255字节且不含控制字符"
                            );
                        }
                    }
                }
                if let Some(tls) = &outbound.tls {
                    ensure!(
                        !tls.ca_file.is_empty()
                            && tls.ca_file.is_ascii()
                            && !tls
                                .ca_file
                                .chars()
                                .any(|ch| ch == '\0' || ch == '\r' || ch == '\n'),
                        "outbounds[{index}].tls.ca_file 必须是非空 ASCII 路径且不含控制字符"
                    );
                    if let Some(name) = &tls.server_name {
                        ensure!(
                            !name.is_empty()
                                && name.len() <= 253
                                && name.is_ascii()
                                && !name
                                    .chars()
                                    .any(|ch| ch.is_ascii_whitespace() || ch == '\0'),
                            "outbounds[{index}].tls.server_name 无效"
                        );
                    }
                }
            } else {
                ensure!(
                    outbound.endpoint.is_none()
                        && outbound.username.is_none()
                        && outbound.password.is_none()
                        && outbound.uuid.is_none()
                        && outbound.encryption.is_none()
                        && outbound.method.is_none()
                        && outbound.security.is_none()
                        && outbound.transport.is_none()
                        && outbound.tls.is_none()
                        && outbound.via.is_none()
                        && outbound.wireguard.is_none()
                        && outbound.hysteria2.is_none()
                        && outbound.tuic.is_none()
                        && outbound.snell.is_none()
                        && outbound.naive.is_none()
                        && outbound.anytls.is_none()
                        && outbound.flow.is_none()
                        && outbound.url.is_none()
                        && !outbound.udp_over_tcp
                        && (outbound.kind == OutboundKind::Reverse || outbound.domain.is_none()),
                    "outbounds[{index}] 的 endpoint/username/password/uuid/method/security/transport/tls/via 仅适用于代理出站"
                );
            }
            if outbound.kind == OutboundKind::Reverse {
                let domain = outbound
                    .domain
                    .as_deref()
                    .ok_or_else(|| anyhow!("outbounds[{index}].domain 不得为空"))?;
                ensure!(
                    !domain.is_empty()
                        && domain.len() <= 253
                        && domain.is_ascii()
                        && !domain
                            .chars()
                            .any(|ch| ch.is_ascii_whitespace() || ch == '\0'),
                    "outbounds[{index}].domain 无效"
                );
            }
            match outbound.kind {
                OutboundKind::Selector => {
                    ensure!(
                        !outbound.outbounds.is_empty() && outbound.outbounds.len() <= 32,
                        "outbounds[{index}].outbounds 必须有 1-32 个成员"
                    );
                    let mut members = HashSet::new();
                    for member in &outbound.outbounds {
                        ensure!(
                            valid_tag(member) && member != &outbound.tag,
                            "outbounds[{index}].outbounds 的成员 tag 无效或指向自身"
                        );
                        ensure!(
                            members.insert(member.as_str()),
                            "outbounds[{index}].outbounds 不得重复"
                        );
                    }
                    if let Some(default) = &outbound.default {
                        ensure!(
                            members.contains(default.as_str()),
                            "outbounds[{index}].default 必须是该 selector 的成员"
                        );
                    }
                    ensure!(
                        outbound.probe.is_none()
                            && outbound.interval_ms.is_none()
                            && outbound.tolerance_ms.is_none()
                            && outbound.probe_timeout_ms.is_none(),
                        "outbounds[{index}] 的 probe/interval_ms/tolerance_ms/probe_timeout_ms 仅适用于 urltest"
                    );
                }
                OutboundKind::Urltest => {
                    ensure!(
                        !outbound.outbounds.is_empty() && outbound.outbounds.len() <= 32,
                        "outbounds[{index}].outbounds 必须有 1-32 个成员"
                    );
                    let mut members = HashSet::new();
                    for member in &outbound.outbounds {
                        ensure!(
                            valid_tag(member) && member != &outbound.tag,
                            "outbounds[{index}].outbounds 的成员 tag 无效或指向自身"
                        );
                        ensure!(
                            members.insert(member.as_str()),
                            "outbounds[{index}].outbounds 不得重复"
                        );
                    }
                    ensure!(
                        outbound.default.is_none(),
                        "outbounds[{index}] 的 default 仅适用于 selector"
                    );
                    let probe = outbound
                        .probe
                        .as_deref()
                        .ok_or_else(|| anyhow!("outbounds[{index}].probe 不得为空"))?;
                    let ambiguous_ipv6 = !probe.starts_with('[') && probe.matches(':').count() > 1;
                    ensure!(
                        !ambiguous_ipv6 && crate::session::parse_endpoint(probe).is_some(),
                        "outbounds[{index}].probe 必须是 HOST:PORT 或 [IPv6]:PORT"
                    );
                    if let Some(value) = outbound.interval_ms {
                        ensure!(
                            (1000..=86_400_000).contains(&value),
                            "outbounds[{index}].interval_ms 必须在 1000-86400000 之间"
                        );
                    }
                    if let Some(value) = outbound.tolerance_ms {
                        ensure!(
                            value <= 60_000,
                            "outbounds[{index}].tolerance_ms 不得超过 60000"
                        );
                    }
                    if let Some(value) = outbound.probe_timeout_ms {
                        ensure!(
                            (100..=60_000).contains(&value),
                            "outbounds[{index}].probe_timeout_ms 必须在 100-60000 之间"
                        );
                    }
                }
                _ => {
                    ensure!(
                        outbound.outbounds.is_empty()
                            && outbound.default.is_none()
                            && outbound.probe.is_none()
                            && outbound.interval_ms.is_none()
                            && outbound.tolerance_ms.is_none()
                            && outbound.probe_timeout_ms.is_none(),
                        "outbounds[{index}] 的 outbounds/default/probe/interval_ms/tolerance_ms/probe_timeout_ms 仅适用于 selector/urltest"
                    );
                }
            }
        }
        let outbound_by_tag: HashMap<&str, &Outbound> = self
            .outbounds
            .iter()
            .map(|outbound| (outbound.tag.as_str(), outbound))
            .collect();
        for (index, outbound) in self.outbounds.iter().enumerate() {
            let Some(via) = &outbound.via else {
                continue;
            };
            ensure!(
                outbound.kind.is_proxy(),
                "outbounds[{index}].via 仅适用于代理出站"
            );
            ensure!(
                outbound.kind != OutboundKind::ShadowTls,
                "outbounds[{index}].via 不适用于 shadowtls 出站"
            );
            ensure!(via != &outbound.tag, "outbounds[{index}].via 不得自引用");
            let next = outbound_by_tag
                .get(via.as_str())
                .ok_or_else(|| anyhow!("outbounds[{index}].via 引用了不存在的出站"))?;
            ensure!(
                next.kind.is_proxy(),
                "outbounds[{index}].via 必须引用代理出站"
            );
            ensure!(
                matches!(
                    next.kind,
                    OutboundKind::Socks5
                        | OutboundKind::Http
                        | OutboundKind::Vless
                        | OutboundKind::Vmess
                        | OutboundKind::Trojan
                        | OutboundKind::Shadowsocks
                        | OutboundKind::Anytls
                        | OutboundKind::Snell
                        | OutboundKind::Naive
                        | OutboundKind::ShadowTls
                ),
                "outbounds[{index}].via 必须引用可建立 TCP 隧道的上游出站"
            );
            if next.kind == OutboundKind::ShadowTls {
                ensure!(
                    next.via.is_none(),
                    "outbounds[{index}].via 引用的 shadowtls 出站不能再配置 via"
                );
                let outbound_endpoint = outbound
                    .endpoint
                    .as_deref()
                    .and_then(crate::session::parse_endpoint)
                    .map(|(host, port)| crate::session::Target { host, port })
                    .ok_or_else(|| anyhow!("outbounds[{index}].endpoint 无效"))?;
                let next_endpoint = next
                    .endpoint
                    .as_deref()
                    .and_then(crate::session::parse_endpoint)
                    .map(|(host, port)| crate::session::Target { host, port })
                    .ok_or_else(|| {
                        anyhow!("outbounds[{index}].via 引用的 shadowtls 出站 endpoint 无效")
                    })?;
                ensure!(
                    outbound_endpoint == next_endpoint,
                    "outbounds[{index}] 与 via 引用的 shadowtls 出站必须使用相同 endpoint"
                );
            }
            ensure!(
                next.naive
                    .as_ref()
                    .is_none_or(|options| options.http_version != NaiveHttpVersion::H3),
                "Naive H3不能作为TCP via跳"
            );
            ensure!(
                !next
                    .transport
                    .as_ref()
                    .is_some_and(|transport| transport.uses_udp_socket())
                    || next.via.is_none(),
                "outbounds[{index}].via 目标 UDP 承载必须是链首直连"
            );
            ensure!(
                matches!(
                    outbound.kind,
                    OutboundKind::Socks5
                        | OutboundKind::Http
                        | OutboundKind::Vless
                        | OutboundKind::Vmess
                        | OutboundKind::Trojan
                        | OutboundKind::Shadowsocks
                        | OutboundKind::Anytls
                        | OutboundKind::Snell
                        | OutboundKind::Naive
                ),
                "outbounds[{index}] 的 via 仅支持 TCP 上游协议"
            );
        }
        for outbound in &self.outbounds {
            let mut seen = HashSet::new();
            let mut current = outbound;
            while let Some(via) = &current.via {
                ensure!(
                    seen.insert(current.tag.as_str()),
                    "outbounds 的 via 存在循环引用"
                );
                current = outbound_by_tag[via.as_str()];
            }
        }
        let mut group_done = HashSet::new();
        for (index, outbound) in self.outbounds.iter().enumerate() {
            if !matches!(
                outbound.kind,
                OutboundKind::Selector | OutboundKind::Urltest
            ) {
                continue;
            }
            for member in &outbound.outbounds {
                ensure!(
                    outbound_by_tag.contains_key(member.as_str()),
                    "outbounds[{index}].outbounds 引用了不存在的出站"
                );
                ensure!(
                    outbound_by_tag[member.as_str()].kind != OutboundKind::Reverse,
                    "outbounds[{index}].outbounds 不得包含 reverse 出站"
                );
                ensure!(
                    outbound_by_tag[member.as_str()].kind != OutboundKind::ShadowTls,
                    "outbounds[{index}].outbounds 不得包含 shadowtls 出站"
                );
                if outbound.kind == OutboundKind::Urltest {
                    ensure!(
                        outbound_by_tag[member.as_str()].kind != OutboundKind::Urltest,
                        "outbounds[{index}].outbounds 的 urltest 成员不得再是 urltest"
                    );
                }
            }
            check_group_cycles(
                &outbound.tag,
                &outbound_by_tag,
                &mut HashSet::new(),
                &mut group_done,
            )?;
        }
        ensure!(
            outbound_tags.contains(self.route.default.as_str()),
            "route.default 引用了不存在的出站"
        );
        ensure!(
            outbound_by_tag[self.route.default.as_str()].kind != OutboundKind::ShadowTls,
            "route.default 不得使用 shadowtls 出站"
        );
        for (index, rule) in self.route.rules.iter().enumerate() {
            ensure!(
                outbound_tags.contains(rule.outbound.as_str()),
                "route.rules[{index}].outbound 引用了不存在的出站"
            );
            ensure!(
                outbound_by_tag[rule.outbound.as_str()].kind != OutboundKind::ShadowTls,
                "route.rules[{index}].outbound 不得使用 shadowtls 出站"
            );
            ensure!(
                rule.inbounds
                    .iter()
                    .all(|tag| inbound_tags.contains(tag.as_str())),
                "route.rules[{index}].inbounds 引用了不存在的入口"
            );
            ensure!(
                rule.ports.iter().all(|range| range.start <= range.end),
                "route.rules[{index}].ports 的起始端口不得大于结束端口"
            );
            // 域名项可以是具体域名，也可以是地理数据集引用
            // （`geosite:cn` / `rule_set:ads`）。
            ensure!(
                rule.domains.iter().all(|domain| {
                    crate::geo::code_of(domain).is_some() || valid_domain(domain)
                }),
                "route.rules[{index}].domains 必须是非空的 ASCII 精确域名或 geosite:/rule_set: 引用"
            );
            // `ip_cidrs` 的字符串项只能是地理引用；其它字符串在这里拒绝，
            // 且错误信息不回显原文（可能是敏感输入）。
            for entry in &rule.ip_cidrs {
                if let crate::config::IpEntry::Geo(value) = entry {
                    ensure!(
                        crate::geo::code_of(value).is_some(),
                        "route.rules[{index}].ip_cidrs 的字符串项必须是 geoip: 或 mmdb: 引用"
                    );
                }
            }
            ensure!(
                rule.domain_suffix
                    .iter()
                    .all(|suffix| valid_domain_fragment(suffix)),
                "route.rules[{index}].domain_suffix 必须是非空 ASCII 域名后缀"
            );
            ensure!(
                rule.domain_keyword.iter().all(|keyword| !keyword.is_empty()
                    && keyword.is_ascii()
                    && !keyword.chars().any(char::is_whitespace)),
                "route.rules[{index}].domain_keyword 必须是非空 ASCII 关键字"
            );
            // 正则在配置加载期就编译，`check` 能直接报错而不是等到起服务。
            for pattern in &rule.domain_regex {
                ensure!(
                    regex::Regex::new(pattern).is_ok(),
                    "route.rules[{index}].domain_regex {pattern:?} 不是合法正则"
                );
            }
            // 没有任何匹配条件又开了 invert，等价于「永不匹配」，几乎肯定是写错了。
            if rule.invert {
                ensure!(
                    !(rule.inbounds.is_empty()
                        && rule.networks.is_empty()
                        && rule.domains.is_empty()
                        && rule.domain_suffix.is_empty()
                        && rule.domain_keyword.is_empty()
                        && rule.ip_cidrs.is_empty()
                        && !rule.ip_is_private
                        && rule.ports.is_empty()),
                    "route.rules[{index}] 使用 invert 时必须至少有一个匹配条件"
                );
            }
        }
        let mut bridge_tags = HashSet::new();
        for (index, bridge) in self.reverse_bridges.iter().enumerate() {
            ensure!(
                valid_tag(&bridge.tag),
                "reverse_bridges[{index}].tag 格式无效"
            );
            ensure!(
                bridge_tags.insert(bridge.tag.as_str()),
                "reverse_bridges[{index}].tag 重复"
            );
            ensure!(
                (100..=600_000).contains(&bridge.reconnect_ms),
                "reverse_bridges[{index}].reconnect_ms 必须在100到600000之间"
            );
            let outbound = outbound_by_tag
                .get(bridge.outbound.as_str())
                .ok_or_else(|| anyhow!("reverse_bridges[{index}].outbound 引用了不存在的出站"))?;
            ensure!(
                outbound.kind == OutboundKind::Vless,
                "reverse_bridges[{index}].outbound 必须是 vless 出站"
            );
        }
        // Xray 写法 `users[].reverse.tag`：声明的 tag 必须指向一个 `reverse`
        // 出站，否则命令 4 在运行期才报错。
        for (index, inbound) in self.inbounds.iter().enumerate() {
            let users = match inbound {
                Inbound::Vless { users, .. } | Inbound::VlessReality { users, .. } => users,
                _ => continue,
            };
            for (user_index, user) in users.iter().enumerate() {
                let Some(reverse) = user.reverse.as_ref() else {
                    continue;
                };
                ensure!(
                    valid_tag(&reverse.tag),
                    "inbounds[{index}].users[{user_index}].reverse.tag 格式无效"
                );
                let target = outbound_by_tag.get(reverse.tag.as_str()).ok_or_else(|| {
                    anyhow!("inbounds[{index}].users[{user_index}].reverse.tag 引用了不存在的出站")
                })?;
                ensure!(
                    target.kind == OutboundKind::Reverse,
                    "inbounds[{index}].users[{user_index}].reverse.tag 必须指向 reverse 出站"
                );
            }
        }
        Ok(())
    }
}

/// 检测 `selector`/`urltest` 的成员引用是否成环；`done` 记录已完成节点，
/// 避免共享成员误报。
fn check_group_cycles(
    tag: &str,
    by_tag: &HashMap<&str, &Outbound>,
    path: &mut HashSet<String>,
    done: &mut HashSet<String>,
) -> Result<()> {
    if done.contains(tag) {
        return Ok(());
    }
    ensure!(
        path.insert(tag.to_owned()),
        "outbounds 的 selector/urltest 存在循环引用"
    );
    if let Some(outbound) = by_tag.get(tag)
        && matches!(
            outbound.kind,
            OutboundKind::Selector | OutboundKind::Urltest
        )
    {
        for member in &outbound.outbounds {
            check_group_cycles(member, by_tag, path, done)?;
        }
    }
    path.remove(tag);
    done.insert(tag.to_owned());
    Ok(())
}

/// NW3 Egress 配置的本地校验；与 Nowhere 的共享密钥、端点约束保持一致。
fn validate_nw3_egress(egress: &Nw3Egress) -> Result<()> {
    ensure!(valid_tag(&egress.tag), "nw3_egress.tag 格式无效");
    ensure!(!egress.endpoint.is_empty(), "nw3_egress.endpoint 不得为空");
    ensure!(
        egress.endpoint.is_ascii()
            && !egress
                .endpoint
                .chars()
                .any(|ch| ch.is_whitespace() || matches!(ch, '?' | '#' | '@')),
        "nw3_egress.endpoint 必须是不含空白、?、#、@ 的 ASCII 端点"
    );
    ensure!(
        egress.key.len() == 32
            && egress
                .key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "nw3_egress.key 必须是32个小写十六进制字符"
    );
    for (name, value) in [("sni", &egress.sni), ("pin", &egress.pin)] {
        if let Some(value) = value {
            ensure!(
                !value.is_empty() && value.is_ascii(),
                "nw3_egress.{name} 必须是非空 ASCII 字符串"
            );
        }
    }
    let dials = [
        egress.dial.is_some(),
        egress.dial4.is_some(),
        egress.dial6.is_some(),
    ];
    ensure!(
        dials.iter().filter(|present| **present).count() <= 1,
        "nw3_egress.dial、dial4、dial6 互斥"
    );
    Ok(())
}

impl Limits {
    fn validate(&self) -> Result<()> {
        // 同时满足 Tokio 的平台限制以及 acquire_many 使用的 u32 范围。
        let max_permits = tokio::sync::Semaphore::MAX_PERMITS.min(u32::MAX as usize);
        for (field, value) in [
            ("max_connections", self.max_connections),
            ("max_handshakes", self.max_handshakes),
            // 0 表示不限制，因此单独放行，不进 `(1..=max)` 区间检查。
            ("per_ip_handshakes", self.per_ip_handshakes.max(1)),
            ("max_udp_associations", self.max_udp_associations),
            ("max_udp_targets", self.max_udp_targets),
            ("udp_queue_packets", self.udp_queue_packets),
            ("max_dns_queries", self.max_dns_queries),
        ] {
            ensure!(
                (1..=max_permits).contains(&value),
                "limits.{field} 超出允许的非零资源范围"
            );
        }
        ensure!(
            (1..=1_048_576).contains(&self.max_replay_entries),
            "limits.max_replay_entries 必须在1到1048576之间"
        );
        ensure!(
            (1..=1_048_576).contains(&self.max_vmess_replay_entries),
            "limits.max_vmess_replay_entries 必须在1到1048576之间"
        );
        ensure!(
            (1..=1_048_576).contains(&self.max_reality_replay_entries),
            "limits.max_reality_replay_entries 必须在1到1048576之间"
        );
        // 队列字节预算最多为 1 GiB，载荷上限适用于 IPv4/IPv6 公共 UDP 路径。
        ensure!(
            (1..=(1 << 30).min(max_permits)).contains(&self.udp_queue_bytes),
            "limits.udp_queue_bytes 超出允许的非零字节范围"
        );
        ensure!(
            (1..=65_507).contains(&self.max_udp_payload),
            "limits.max_udp_payload 必须在 1 到 65507 之间"
        );
        ensure!(
            (1..=max_permits).contains(&self.max_grpc_streams),
            "limits.max_grpc_streams 超出允许的非零资源范围"
        );
        ensure!(
            (1..=128).contains(&self.max_grpc_streams_per_connection),
            "limits.max_grpc_streams_per_connection 必须在1到128之间"
        );
        ensure!(
            self.max_grpc_streams_per_connection <= self.max_grpc_streams,
            "limits.max_grpc_streams_per_connection 不得超过 limits.max_grpc_streams"
        );
        ensure!(
            (1..=max_permits).contains(&self.max_xhttp_sessions),
            "limits.max_xhttp_sessions 超出允许的非零资源范围"
        );
        for (field, value) in [
            ("handshake_timeout_ms", self.handshake_timeout_ms),
            ("dial_timeout_ms", self.dial_timeout_ms),
            ("dial_attempt_timeout_ms", self.dial_attempt_timeout_ms),
            ("dns_timeout_ms", self.dns_timeout_ms),
            ("udp_idle_timeout_ms", self.udp_idle_timeout_ms),
            ("shutdown_timeout_ms", self.shutdown_timeout_ms),
            ("stats_interval_ms", self.stats_interval_ms),
        ] {
            ensure!(
                (1..=86_400_000).contains(&value),
                "limits.{field} 必须为非零毫秒数且不超过一天"
            );
        }
        // 0 是显式的「不限制」，与其它非零超时字段不同。
        ensure!(
            self.idle_timeout_ms <= 86_400_000,
            "limits.idle_timeout_ms 不得超过一天（0 表示不限制）"
        );
        Ok(())
    }
}

fn valid_tag(tag: &str) -> bool {
    // 日志及引用使用简洁标识符，不允许空白、控制字符或转义分隔符。
    !tag.is_empty()
        && tag.len() <= 128
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// 后缀片段允许前导点（`.example.com`）与普通域名，其余规则同 `valid_domain`。
fn valid_domain_fragment(value: &str) -> bool {
    let value = value.strip_prefix('.').unwrap_or(value);
    valid_domain(value)
}

fn valid_domain(domain: &str) -> bool {
    // 国际化域名使用 ASCII 编码；仅接受精确匹配，不隐式支持通配符。
    let domain = domain.trim_end_matches('.');
    !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

/// ShadowTLS 的内层协议必须是明文入站；TLS 由 ShadowTLS 自身伪装承担。
fn shadowtls_detour_allowed(inbound: &Inbound) -> bool {
    match inbound {
        Inbound::Shadowsocks { .. }
        | Inbound::Snell { .. }
        | Inbound::Socks5 { .. }
        | Inbound::Http { .. }
        | Inbound::Mixed { .. } => true,
        Inbound::Vmess {
            certificate,
            private_key,
            ..
        } => certificate.is_none() && private_key.is_none(),
        _ => false,
    }
}

/// REALITY 与证书互斥；返回该入口是否使用 REALITY。
/// Xray REALITY 仅支持 RAW、XHTTP、gRPC；WS/HTTPUpgrade 是本项目不应提供的
/// 非上游组合，必须在配置阶段拒绝，而不是等握手后才失败。
fn reject_reality_transport(
    reality: Option<&Reality>,
    transport: &str,
    inbound_index: usize,
) -> Result<()> {
    ensure!(
        reality.is_none(),
        "inbounds[{inbound_index}] REALITY 仅支持 RAW、XHTTP、gRPC 传输，不支持 {transport}"
    );
    Ok(())
}

fn validate_reality_transport(
    reality: Option<&Reality>,
    certificate: Option<&Path>,
    private_key: Option<&Path>,
    allow_insecure: bool,
    inbound_index: usize,
) -> Result<bool> {
    let Some(reality) = reality else {
        return Ok(false);
    };
    ensure!(
        certificate.is_none() && private_key.is_none(),
        "inbounds[{inbound_index}] REALITY 不能与 certificate/private_key 同时配置"
    );
    ensure!(
        !allow_insecure,
        "inbounds[{inbound_index}] 配置 REALITY 时不得设置 allow_insecure_transport"
    );
    reality.prepare()?;
    Ok(true)
}

pub(super) fn validate_users(users: &[User], socks5: bool, inbound_index: usize) -> Result<()> {
    let mut names = HashSet::new();
    let mut passwords = HashSet::new();
    for (user_index, user) in users.iter().enumerate() {
        ensure!(
            !user.name.is_empty() && !user.password.is_empty(),
            "inbounds[{inbound_index}].users[{user_index}] 用户名和密码不得为空"
        );
        ensure!(
            names.insert(user.name.as_str()),
            "inbounds[{inbound_index}].users[{user_index}] 用户名重复"
        );
        ensure!(
            passwords.insert(user.password.as_str()),
            "inbounds[{inbound_index}].users[{user_index}] 密码重复"
        );
        // RFC 1929 的长度是字节数，不能按 Unicode 字符数计数。
        ensure!(
            !socks5 || (user.name.len() <= 255 && user.password.len() <= 255),
            "inbounds[{inbound_index}].users[{user_index}] SOCKS5 凭据不得超过 255 字节"
        );
    }
    Ok(())
}

/// VLESS Encryption 的 `decryption` 只校验语法；与 Vision flow 可组合。
fn validate_vless_decryption(decryption: Option<&str>) -> Result<()> {
    let Some(value) = decryption else {
        return Ok(());
    };
    vless_encryption::parse(value)?;
    Ok(())
}

fn validate_vless_users(users: &[VlessUser], inbound_index: usize) -> Result<()> {
    let mut names = HashSet::new();
    let mut uuids = HashSet::new();
    for (user_index, user) in users.iter().enumerate() {
        ensure!(
            !user.name.is_empty(),
            "inbounds[{inbound_index}].users[{user_index}] 用户名不得为空"
        );
        ensure!(
            names.insert(user.name.as_str()),
            "inbounds[{inbound_index}].users[{user_index}] 用户名重复"
        );
        let uuid = parse_uuid(&user.uuid).ok_or_else(|| {
            anyhow!("inbounds[{inbound_index}].users[{user_index}] UUID 必须为标准 36 字符格式")
        })?;
        ensure!(
            uuids.insert(uuid),
            "inbounds[{inbound_index}].users[{user_index}] UUID 重复"
        );
    }
    Ok(())
}

fn sanitize_json_error(error: serde_json::Error) -> anyhow::Error {
    use serde_json::error::Category;

    let reason = match error.classify() {
        Category::Io => "JSON 读取失败",
        Category::Syntax => "JSON 语法错误",
        Category::Eof => "JSON 输入不完整",
        Category::Data => {
            // 原始 Serde 诊断可能含密码、未知键或完整输入值；仅取固定类别。
            let message = error.to_string();
            if message.starts_with("unknown field") {
                "存在未知字段或尚未实现的选项"
            } else if message.starts_with("unknown variant") {
                "协议或枚举类型不受支持"
            } else if message.starts_with("missing field") {
                "缺少必填字段"
            } else if message.starts_with("duplicate field") {
                "字段重复"
            } else if message.starts_with("invalid type") {
                "字段类型不正确"
            } else {
                "字段结构、类型或取值无效"
            }
        }
    };
    // 不保留原始错误链，避免上层使用 Debug 或完整错误链时泄漏输入。
    anyhow!(
        "配置 JSON 错误：{reason}（line {}, column {}）",
        error.line(),
        error.column()
    )
}
