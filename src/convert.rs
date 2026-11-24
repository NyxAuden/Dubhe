//! 把 Xray 配置一次性转换成 dubhe 配置。
//!
//! 只覆盖「入口/出站基本字段 + 静态路由」；高级语义（fallback、balancer、
//! 多级 routing action、downloadSettings 等）显式报错而不是静默丢弃。
//! 转换结果会再走一遍 `Config::from_json`，因此不可能输出无法启动的配置。

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};

use crate::config::Config;

/// 转换过程中的提示；调用方负责打印或写文件。
#[derive(Debug, Default)]
pub struct Report {
    pub notes: Vec<String>,
}

impl Report {
    fn note(&mut self, message: impl Into<String>) {
        self.notes.push(message.into());
    }
}

/// 转换结果：`json` 是只含显式字段的输出，`config` 是校验后的强类型视图。
#[derive(Debug)]
pub struct Converted {
    pub config: Config,
    pub json: Value,
    pub report: Report,
}

/// 转换 Xray JSON。`ca_file` 用于所有带 TLS 的出站：本项目不接受系统根证书
/// 隐式信任，必须显式给出信任锚。
pub fn from_xray(input: &str, ca_file: Option<&str>) -> Result<Converted> {
    let root: Value = serde_json::from_str(input).context("Xray 配置不是合法 JSON")?;
    let object = root
        .as_object()
        .ok_or_else(|| anyhow!("Xray 配置根节点必须是对象"))?;
    let mut report = Report::default();

    let inbounds = convert_inbounds(object.get("inbounds"), &mut report)?;
    let outbounds = convert_outbounds(object.get("outbounds"), ca_file, &mut report)?;
    let route = convert_routing(object.get("routing"), &outbounds, &mut report)?;

    let mut output = Map::new();
    output.insert("version".into(), json!(1));
    output.insert("inbounds".into(), Value::Array(inbounds));
    output.insert("outbounds".into(), Value::Array(outbounds));
    output.insert("route".into(), route);

    let json = Value::Object(output);
    let text = serde_json::to_string(&json)?;
    let config =
        Config::from_json(&text).map_err(|error| anyhow!("转换结果未通过 dubhe 校验：{error}"))?;
    Ok(Converted {
        config,
        json,
        report,
    })
}

fn convert_inbounds(value: Option<&Value>, report: &mut Report) -> Result<Vec<Value>> {
    let Some(value) = value else {
        bail!("Xray 配置缺少 inbounds");
    };
    let items = value
        .as_array()
        .ok_or_else(|| anyhow!("inbounds 必须是数组"))?;
    let mut output = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        output.push(convert_inbound(item, index, report)?);
    }
    Ok(output)
}

fn convert_inbound(item: &Value, index: usize, report: &mut Report) -> Result<Value> {
    let object = item
        .as_object()
        .ok_or_else(|| anyhow!("inbounds[{index}] 必须是对象"))?;
    let protocol =
        string(item, "protocol").ok_or_else(|| anyhow!("inbounds[{index}] 缺少 protocol"))?;
    let tag = string(item, "tag")
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{protocol}-{index}"));
    let port = number(item, "port").ok_or_else(|| anyhow!("inbounds[{index}] 缺少 port"))?;
    let listen = string(item, "listen").unwrap_or("0.0.0.0");
    let address = endpoint(listen, port)?;

    let stream = object.get("streamSettings");
    let network = stream
        .and_then(|s| s.get("network"))
        .and_then(Value::as_str)
        .unwrap_or("tcp");
    let security = stream
        .and_then(|s| s.get("security"))
        .and_then(Value::as_str)
        .unwrap_or("none");

    let settings = object.get("settings").cloned().unwrap_or_else(|| json!({}));
    let mut out = Map::new();
    out.insert("tag".into(), json!(tag));
    out.insert("listen".into(), json!(address));

    match protocol {
        "vless" => {
            let users = vless_users(&settings, index)?;
            out.insert("users".into(), Value::Array(users));
            apply_decryption(&settings, &mut out, report)?;
            match (network, security) {
                ("tcp", "none") => {
                    out.insert("type".into(), json!("vless"));
                }
                ("tcp", "tls") => {
                    out.insert("type".into(), json!("vless"));
                    apply_certificate(stream, &mut out, index)?;
                }
                ("tcp", "reality") => {
                    out.insert("type".into(), json!("vless-reality"));
                    out.insert("reality".into(), convert_reality_in(stream, index)?);
                }
                ("ws", "tls") => {
                    out.insert("type".into(), json!("vless-ws"));
                    out.insert("websocket".into(), convert_websocket(stream));
                    apply_certificate(stream, &mut out, index)?;
                }
                ("grpc", "tls") => {
                    out.insert("type".into(), json!("vless-grpc"));
                    out.insert("grpc".into(), convert_grpc(stream, index)?);
                    apply_certificate(stream, &mut out, index)?;
                }
                ("xhttp", "tls") => {
                    out.insert("type".into(), json!("vless-xhttp"));
                    out.insert("xhttp".into(), convert_xhttp(stream, index)?);
                    apply_certificate(stream, &mut out, index)?;
                }
                ("httpupgrade", "tls") => {
                    out.insert("type".into(), json!("vless-httpupgrade"));
                    out.insert("httpupgrade".into(), convert_httpupgrade(stream, index)?);
                    apply_certificate(stream, &mut out, index)?;
                }
                ("kcp", "none") => {
                    out.insert("type".into(), json!("vless-kcp"));
                    report.note(format!(
                        "inbounds[{index}] 的 mKCP 参数按本项目默认值生成，请核对 mtu/tti/header"
                    ));
                }
                (network, security) => bail!(
                    "inbounds[{index}] 的 VLESS 组合 network={network} security={security} 暂不支持转换"
                ),
            }
        }
        "vmess" => {
            let users = vmess_users(&settings, index)?;
            out.insert("users".into(), Value::Array(users));
            match (network, security) {
                ("tcp", "none") | ("tcp", "tls") => {
                    out.insert("type".into(), json!("vmess"));
                    if security == "tls" {
                        apply_certificate(stream, &mut out, index)?;
                    }
                }
                ("ws", "tls") => {
                    out.insert("type".into(), json!("vmess-ws"));
                    out.insert("websocket".into(), convert_websocket(stream));
                    apply_certificate(stream, &mut out, index)?;
                }
                ("tcp", "reality") => {
                    out.insert("type".into(), json!("vmess-reality"));
                    out.insert("reality".into(), convert_reality_in(stream, index)?);
                }
                ("grpc", "tls") => {
                    out.insert("type".into(), json!("vmess-grpc"));
                    out.insert("grpc".into(), convert_grpc(stream, index)?);
                    apply_certificate(stream, &mut out, index)?;
                }
                ("xhttp", "tls") => {
                    out.insert("type".into(), json!("vmess-xhttp"));
                    out.insert("xhttp".into(), convert_xhttp(stream, index)?);
                    apply_certificate(stream, &mut out, index)?;
                }
                ("httpupgrade", "tls") => {
                    out.insert("type".into(), json!("vmess-httpupgrade"));
                    out.insert("httpupgrade".into(), convert_httpupgrade(stream, index)?);
                    apply_certificate(stream, &mut out, index)?;
                }
                (network, security) => bail!(
                    "inbounds[{index}] 的 VMess 组合 network={network} security={security} 暂不支持转换"
                ),
            }
        }
        "trojan" => {
            let users = trojan_users(&settings, index)?;
            out.insert("users".into(), Value::Array(users));
            match (network, security) {
                ("tcp", "tls") => {
                    out.insert("type".into(), json!("trojan"));
                    apply_certificate(stream, &mut out, index)?;
                }
                ("ws", "tls") => {
                    out.insert("type".into(), json!("trojan-ws"));
                    out.insert("websocket".into(), convert_websocket(stream));
                    apply_certificate(stream, &mut out, index)?;
                }
                ("tcp", "reality") => {
                    out.insert("type".into(), json!("trojan-reality"));
                    out.insert("reality".into(), convert_reality_in(stream, index)?);
                }
                ("grpc", "tls") => {
                    out.insert("type".into(), json!("trojan-grpc"));
                    out.insert("grpc".into(), convert_grpc(stream, index)?);
                    apply_certificate(stream, &mut out, index)?;
                }
                ("xhttp", "tls") => {
                    out.insert("type".into(), json!("trojan-xhttp"));
                    out.insert("xhttp".into(), convert_xhttp(stream, index)?);
                    apply_certificate(stream, &mut out, index)?;
                }
                ("httpupgrade", "tls") => {
                    out.insert("type".into(), json!("trojan-httpupgrade"));
                    out.insert("httpupgrade".into(), convert_httpupgrade(stream, index)?);
                    apply_certificate(stream, &mut out, index)?;
                }
                (network, security) => bail!(
                    "inbounds[{index}] 的 Trojan 组合 network={network} security={security} 暂不支持转换"
                ),
            }
        }
        "shadowsocks" => {
            out.insert("type".into(), json!("shadowsocks"));
            let method = string(&settings, "method")
                .ok_or_else(|| anyhow!("inbounds[{index}] 的 Shadowsocks 缺少 method"))?;
            let password = string(&settings, "password")
                .ok_or_else(|| anyhow!("inbounds[{index}] 的 Shadowsocks 缺少 password"))?;
            out.insert("method".into(), json!(method));
            out.insert("password".into(), json!(password));
            report.note(format!(
                "inbounds[{index}] Shadowsocks 只转换单密码；Xray 的 clients 多用户未映射"
            ));
        }
        "socks" => {
            out.insert("type".into(), json!("socks5"));
            let users = account_users(&settings)?;
            require_auth_or_loopback(&address, &users, index)?;
            out.insert("users".into(), Value::Array(users));
        }
        "http" => {
            out.insert("type".into(), json!("http"));
            let users = account_users(&settings)?;
            require_auth_or_loopback(&address, &users, index)?;
            out.insert("users".into(), Value::Array(users));
        }
        other => bail!("inbounds[{index}] 的协议 {other} 暂不支持转换"),
    }

    if object.get("fallbacks").is_some() || settings.get("fallbacks").is_some() {
        bail!("inbounds[{index}] 含 fallbacks，转换会改变回落语义，请手工配置");
    }

    Ok(Value::Object(out))
}

fn vless_users(settings: &Value, index: usize) -> Result<Vec<Value>> {
    let clients = settings
        .get("clients")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("inbounds[{index}] 的 VLESS 缺少 clients"))?;
    let mut users = Vec::with_capacity(clients.len());
    for (position, client) in clients.iter().enumerate() {
        let id = string(client, "id")
            .ok_or_else(|| anyhow!("inbounds[{index}].clients[{position}] 缺少 id"))?;
        let name = string(client, "email")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("user{position}"));
        let flow = string(client, "flow").unwrap_or("");
        let mut user = Map::new();
        user.insert("name".into(), json!(name));
        user.insert("uuid".into(), json!(id));
        if flow == "xtls-rprx-vision" {
            user.insert("flow".into(), json!("xtls-rprx-vision"));
        } else if !flow.is_empty() {
            bail!("inbounds[{index}] 的 flow={flow} 暂不支持转换");
        }
        users.push(Value::Object(user));
    }
    Ok(users)
}

fn vmess_users(settings: &Value, index: usize) -> Result<Vec<Value>> {
    let clients = settings
        .get("clients")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("inbounds[{index}] 的 VMess 缺少 clients"))?;
    let mut users = Vec::with_capacity(clients.len());
    for (position, client) in clients.iter().enumerate() {
        let id = string(client, "id")
            .ok_or_else(|| anyhow!("inbounds[{index}].clients[{position}] 缺少 id"))?;
        let name = string(client, "email")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("user{position}"));
        users.push(json!({"name": name, "uuid": id}));
    }
    Ok(users)
}

fn trojan_users(settings: &Value, index: usize) -> Result<Vec<Value>> {
    let clients = settings
        .get("clients")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("inbounds[{index}] 的 Trojan 缺少 clients"))?;
    let mut users = Vec::with_capacity(clients.len());
    for (position, client) in clients.iter().enumerate() {
        let password = string(client, "password")
            .ok_or_else(|| anyhow!("inbounds[{index}].clients[{position}] 缺少 password"))?;
        let name = string(client, "email")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("user{position}"));
        users.push(json!({"name": name, "password": password}));
    }
    Ok(users)
}

fn account_users(settings: &Value) -> Result<Vec<Value>> {
    let Some(accounts) = settings.get("accounts").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut users = Vec::with_capacity(accounts.len());
    for account in accounts {
        let name = string(account, "user").unwrap_or("");
        let password = string(account, "pass").unwrap_or("");
        users.push(json!({"name": name, "password": password}));
    }
    Ok(users)
}

/// 无认证的 SOCKS/HTTP 入口默认只允许回环；非回环必须显式允许，
/// 转换层不替用户做这个安全决定。
fn require_auth_or_loopback(address: &str, users: &[Value], index: usize) -> Result<()> {
    if !users.is_empty() {
        return Ok(());
    }
    let host = address
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(address);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = host
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false);
    if loopback {
        return Ok(());
    }
    bail!(
        "inbounds[{index}] 是无认证的 SOCKS/HTTP 且监听非回环 {address}；\n         请在源配置添加 accounts，或转换后手工设置 allow_insecure 并自行承担风险"
    )
}

fn apply_decryption(
    settings: &Value,
    out: &mut Map<String, Value>,
    report: &mut Report,
) -> Result<()> {
    let Some(decryption) = string(settings, "decryption") else {
        return Ok(());
    };
    if decryption == "none" {
        return Ok(());
    }
    if decryption.starts_with("mlkem768x25519plus") {
        out.insert("decryption".into(), json!(decryption));
        report.note("VLESS Encryption 已原样保留，请核对与 fallbacks 的互斥".to_owned());
        return Ok(());
    }
    bail!("不支持的 VLESS decryption={decryption}");
}

fn apply_certificate(
    stream: Option<&Value>,
    out: &mut Map<String, Value>,
    index: usize,
) -> Result<()> {
    let (certificate, private_key) = certificate_paths(stream)
        .ok_or_else(|| anyhow!("inbounds[{index}] 使用 TLS 但缺少 certificateFile/keyFile"))?;
    out.insert("certificate".into(), json!(certificate));
    out.insert("private_key".into(), json!(private_key));
    Ok(())
}

fn certificate_paths(stream: Option<&Value>) -> Option<(String, String)> {
    let certificates = stream?
        .get("tlsSettings")?
        .get("certificates")?
        .as_array()?;
    let first = certificates.first()?;
    Some((
        string(first, "certificateFile")?.to_owned(),
        string(first, "keyFile")?.to_owned(),
    ))
}

fn convert_websocket(stream: Option<&Value>) -> Value {
    let settings = stream.and_then(|s| s.get("wsSettings"));
    let path = settings
        .and_then(|s| s.get("path"))
        .and_then(Value::as_str)
        .unwrap_or("/");
    let host = settings
        .and_then(|s| s.get("headers"))
        .and_then(|h| h.get("Host"))
        .and_then(Value::as_str);
    let mut out = Map::new();
    out.insert("path".into(), json!(path));
    if let Some(host) = host {
        out.insert("host".into(), json!(host));
    }
    Value::Object(out)
}

/// Xray 的 `serviceName` → 完整 HTTP/2 路径。
///
/// 本仓库的 `grpc.path` 存完整路径（`/GunService/Tun`）。Xray 老式写法只给服务名，
/// 客户端请求 `/<service>/Tun`（multiMode 为 `/<service>/TunMulti`）；以 `/` 开头
/// 是新式完整路径，服务端用 `单路径|多路径` 给出 multi 路径。
fn grpc_paths(service: &str) -> (String, Option<String>) {
    if let Some(rest) = service.strip_prefix('/') {
        return match rest.split_once('|') {
            Some((single, multi)) => (format!("/{single}"), Some(format!("/{multi}"))),
            None => (format!("/{rest}"), None),
        };
    }
    (
        format!("/{service}/Tun"),
        Some(format!("/{service}/TunMulti")),
    )
}

fn convert_grpc(stream: Option<&Value>, index: usize) -> Result<Value> {
    let settings = stream.and_then(|s| s.get("grpcSettings"));
    let service = settings
        .and_then(|s| s.get("serviceName"))
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow!("inbounds[{index}] 的 gRPC 缺少 serviceName"))?;
    let multi_mode = settings
        .and_then(|s| s.get("multiMode"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (path, multi_path) = grpc_paths(service);
    if multi_mode && multi_path.is_none() {
        bail!(
            "inbounds[{index}] 的 gRPC 使用新式完整路径 + multiMode，\
             但 serviceName 缺少 `单路径|多路径` 分隔；无法推导 multi_path"
        );
    }
    let mut out = Map::new();
    out.insert("path".into(), json!(path));
    if multi_mode && let Some(multi_path) = multi_path {
        out.insert("multi_path".into(), json!(multi_path));
    }
    Ok(Value::Object(out))
}

fn convert_xhttp(stream: Option<&Value>, index: usize) -> Result<Value> {
    let settings = stream
        .and_then(|s| s.get("xhttpSettings"))
        .ok_or_else(|| anyhow!("inbounds[{index}] 的 XHTTP 缺少 xhttpSettings"))?;
    let path = string(settings, "path").unwrap_or("/");
    let mut out = Map::new();
    out.insert("path".into(), json!(path));
    if let Some(host) = string(settings, "host") {
        out.insert("host".into(), json!(host));
    }
    if let Some(mode) = string(settings, "mode") {
        out.insert("mode".into(), json!(mode));
    }
    let extra = settings.get("extra");
    if extra.is_some_and(|value| {
        value
            .as_object()
            .is_some_and(|object| object.contains_key("downloadSettings"))
    }) {
        bail!("inbounds[{index}] 的 XHTTP downloadSettings 未实现，转换会改变下行语义");
    }
    let headers = settings
        .get("headers")
        .and_then(Value::as_object)
        .map(|object| {
            object
                .iter()
                .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), json!(value))))
                .collect::<Map<String, Value>>()
        });
    if let Some(headers) = headers.filter(|headers| !headers.is_empty()) {
        out.insert("headers".into(), Value::Object(headers));
    }
    Ok(Value::Object(out))
}

fn convert_httpupgrade(stream: Option<&Value>, index: usize) -> Result<Value> {
    let settings = stream
        .and_then(|s| s.get("httpupgradeSettings"))
        .ok_or_else(|| anyhow!("inbounds[{index}] 的 HTTPUpgrade 缺少 httpupgradeSettings"))?;
    let path = string(settings, "path").unwrap_or("/");
    let mut out = Map::new();
    out.insert("path".into(), json!(path));
    if let Some(host) = string(settings, "host") {
        out.insert("host".into(), json!(host));
    }
    Ok(Value::Object(out))
}

fn convert_reality_in(stream: Option<&Value>, index: usize) -> Result<Value> {
    let settings = stream
        .and_then(|s| s.get("realitySettings"))
        .ok_or_else(|| anyhow!("inbounds[{index}] 使用 REALITY 但缺少 realitySettings"))?;
    let dest = string(settings, "dest")
        .ok_or_else(|| anyhow!("inbounds[{index}] 的 REALITY 缺少 dest"))?;
    let (host, port) = split_endpoint(dest)?;
    let server_names = string_array(settings, "serverNames");
    let short_ids = string_array(settings, "shortIds");
    let private_key = string(settings, "privateKey")
        .ok_or_else(|| anyhow!("inbounds[{index}] 的 REALITY 缺少 privateKey"))?;
    Ok(json!({
        "target": {"host": host, "port": port},
        "private_key": private_key,
        "server_names": server_names,
        "short_ids": short_ids,
    }))
}

fn convert_outbounds(
    value: Option<&Value>,
    ca_file: Option<&str>,
    report: &mut Report,
) -> Result<Vec<Value>> {
    let Some(value) = value else {
        return Ok(vec![json!({"tag": "direct", "type": "direct"})]);
    };
    let items = value
        .as_array()
        .ok_or_else(|| anyhow!("outbounds 必须是数组"))?;
    let mut output = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        output.push(convert_outbound(item, index, ca_file, report)?);
    }
    Ok(output)
}

fn convert_outbound(
    item: &Value,
    index: usize,
    ca_file: Option<&str>,
    report: &mut Report,
) -> Result<Value> {
    let object = item
        .as_object()
        .ok_or_else(|| anyhow!("outbounds[{index}] 必须是对象"))?;
    let protocol =
        string(item, "protocol").ok_or_else(|| anyhow!("outbounds[{index}] 缺少 protocol"))?;
    let tag = string(item, "tag")
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{protocol}-{index}"));
    let settings = object.get("settings").cloned().unwrap_or_else(|| json!({}));
    let stream = object.get("streamSettings");
    if let Some(chain) = stream
        .and_then(|s| s.get("sockopt"))
        .and_then(|s| s.get("dialerProxy"))
        .and_then(Value::as_str)
    {
        // 丢掉 dialerProxy 会让这条出站直连，等于跳过用户配置的链式代理。
        bail!(
            "outbounds[{index}] 使用 sockopt.dialerProxy={chain} 链式代理；\
             转换无法等价表达，请改用 dubhe 的 via 字段手工配置"
        );
    }

    match protocol {
        "freedom" => Ok(json!({"tag": tag, "type": "direct"})),
        "blackhole" => Ok(json!({"tag": tag, "type": "reject"})),
        "vless" => {
            let (endpoint, user) = first_vnext(&settings, index)?;
            let mut out = Map::new();
            out.insert("tag".into(), json!(tag));
            out.insert("type".into(), json!("vless"));
            out.insert("endpoint".into(), json!(endpoint));
            out.insert(
                "uuid".into(),
                json!(string(user, "id").ok_or_else(|| anyhow!("outbounds[{index}] 缺少 id"))?),
            );
            if string(user, "flow") == Some("xtls-rprx-vision") {
                out.insert("flow".into(), json!("xtls-rprx-vision"));
            }
            apply_outbound_security(stream, &mut out, index, ca_file, report)?;
            apply_outbound_transport(stream, &mut out, index)?;
            Ok(Value::Object(out))
        }
        "vmess" => {
            let (endpoint, user) = first_vnext(&settings, index)?;
            let mut out = Map::new();
            out.insert("tag".into(), json!(tag));
            out.insert("type".into(), json!("vmess"));
            out.insert("endpoint".into(), json!(endpoint));
            out.insert(
                "uuid".into(),
                json!(string(user, "id").ok_or_else(|| anyhow!("outbounds[{index}] 缺少 id"))?),
            );
            if let Some(security) = user.get("security").and_then(Value::as_u64) {
                out.insert("security".into(), json!(security));
            }
            apply_outbound_security(stream, &mut out, index, ca_file, report)?;
            apply_outbound_transport(stream, &mut out, index)?;
            Ok(Value::Object(out))
        }
        "trojan" => {
            let server = first_server(&settings, index)?;
            let mut out = Map::new();
            out.insert("tag".into(), json!(tag));
            out.insert("type".into(), json!("trojan"));
            out.insert("endpoint".into(), json!(server_endpoint(server, index)?));
            out.insert(
                "password".into(),
                json!(
                    string(server, "password")
                        .ok_or_else(|| anyhow!("outbounds[{index}] 缺少 password"))?
                ),
            );
            apply_outbound_security(stream, &mut out, index, ca_file, report)?;
            apply_outbound_transport(stream, &mut out, index)?;
            Ok(Value::Object(out))
        }
        "shadowsocks" => {
            let server = first_server(&settings, index)?;
            let mut out = Map::new();
            out.insert("tag".into(), json!(tag));
            out.insert("type".into(), json!("shadowsocks"));
            out.insert("endpoint".into(), json!(server_endpoint(server, index)?));
            out.insert(
                "method".into(),
                json!(
                    string(server, "method")
                        .ok_or_else(|| anyhow!("outbounds[{index}] 缺少 method"))?
                ),
            );
            out.insert(
                "password".into(),
                json!(
                    string(server, "password")
                        .ok_or_else(|| anyhow!("outbounds[{index}] 缺少 password"))?
                ),
            );
            apply_plain_outbound_wrapping(stream, &mut out, index, protocol, ca_file, report)?;
            Ok(Value::Object(out))
        }
        "socks" => {
            let server = first_server(&settings, index)?;
            let mut out = Map::new();
            out.insert("tag".into(), json!(tag));
            out.insert("type".into(), json!("socks5"));
            out.insert("endpoint".into(), json!(server_endpoint(server, index)?));
            if let Some(users) = server.get("users").and_then(Value::as_array)
                && let Some(user) = users.first()
            {
                if let Some(name) = string(user, "user") {
                    out.insert("username".into(), json!(name));
                }
                if let Some(password) = string(user, "pass") {
                    out.insert("password".into(), json!(password));
                }
            }
            apply_plain_outbound_wrapping(stream, &mut out, index, protocol, ca_file, report)?;
            Ok(Value::Object(out))
        }
        "http" => {
            let server = first_server(&settings, index)?;
            let mut out = Map::new();
            out.insert("tag".into(), json!(tag));
            out.insert("type".into(), json!("http"));
            out.insert("endpoint".into(), json!(server_endpoint(server, index)?));
            if let Some(users) = server.get("users").and_then(Value::as_array)
                && let Some(user) = users.first()
            {
                if let Some(name) = string(user, "user") {
                    out.insert("username".into(), json!(name));
                }
                if let Some(password) = string(user, "pass") {
                    out.insert("password".into(), json!(password));
                }
            }
            apply_plain_outbound_wrapping(stream, &mut out, index, protocol, ca_file, report)?;
            Ok(Value::Object(out))
        }
        other => bail!("outbounds[{index}] 的协议 {other} 暂不支持转换"),
    }
}

/// socks/http/shadowsocks 出站在 dubhe 里支持 TLS，但不支持 REALITY 与自定义承载。
///
/// Xray 对这三类出站也套用 `streamSettings`；此前转换器直接跳过，带 TLS 的
/// 上游被静默降成明文，而退出码仍是 0。
fn apply_plain_outbound_wrapping(
    stream: Option<&Value>,
    out: &mut Map<String, Value>,
    index: usize,
    protocol: &str,
    ca_file: Option<&str>,
    report: &mut Report,
) -> Result<()> {
    let network = stream
        .and_then(|s| s.get("network"))
        .and_then(Value::as_str)
        .unwrap_or("tcp");
    anyhow::ensure!(
        network == "tcp",
        "outbounds[{index}] 的 {protocol} 出站使用 network={network} 承载，\
         dubhe 的该类出站只支持原始 TCP；请改用 vless/vmess/trojan 出站"
    );
    let security = stream
        .and_then(|s| s.get("security"))
        .and_then(Value::as_str)
        .unwrap_or("none");
    anyhow::ensure!(
        security != "reality",
        "outbounds[{index}] 的 {protocol} 出站使用 REALITY，\
         dubhe 的该类出站不支持 REALITY；请改用 vless/vmess/trojan 出站"
    );
    if security == "tls" && protocol == "shadowsocks" {
        bail!(
            "outbounds[{index}] 的 shadowsocks 出站使用 TLS，dubhe 的 shadowsocks 出站不支持 TLS；\
             请改用 socks/http 出站或在上游终止 TLS"
        );
    }
    apply_outbound_security(stream, out, index, ca_file, report)
}

fn apply_outbound_security(
    stream: Option<&Value>,
    out: &mut Map<String, Value>,
    index: usize,
    ca_file: Option<&str>,
    report: &mut Report,
) -> Result<()> {
    let security = stream
        .and_then(|s| s.get("security"))
        .and_then(Value::as_str)
        .unwrap_or("none");
    match security {
        "none" => Ok(()),
        "tls" => {
            let ca_file = ca_file.ok_or_else(|| {
                anyhow!("outbounds[{index}] 使用 TLS；请用 --ca-file 指定信任锚 PEM")
            })?;
            let server_name = stream
                .and_then(|s| s.get("tlsSettings"))
                .and_then(|s| s.get("serverName"))
                .and_then(Value::as_str);
            let mut tls = Map::new();
            tls.insert("ca_file".into(), json!(ca_file));
            if let Some(server_name) = server_name {
                tls.insert("server_name".into(), json!(server_name));
            }
            out.insert("tls".into(), Value::Object(tls));
            Ok(())
        }
        "reality" => {
            let settings = stream
                .and_then(|s| s.get("realitySettings"))
                .ok_or_else(|| anyhow!("outbounds[{index}] 使用 REALITY 但缺少 realitySettings"))?;
            let inner = settings
                .get("settings")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let public_key = string(&inner, "publicKey")
                .ok_or_else(|| anyhow!("outbounds[{index}] 的 REALITY 缺少 publicKey"))?;
            let server_name = string(settings, "serverName")
                .ok_or_else(|| anyhow!("outbounds[{index}] 的 REALITY 缺少 serverName"))?;
            let short_id = string(settings, "shortId").unwrap_or("");
            out.insert(
                "reality".into(),
                json!({
                    "public_key": public_key,
                    "server_name": server_name,
                    "short_id": short_id,
                }),
            );
            report.note(format!(
                "outbounds[{index}] REALITY 的 fingerprint 与 version 使用本项目默认值"
            ));
            Ok(())
        }
        other => bail!("outbounds[{index}] 的 security={other} 暂不支持转换"),
    }
}

fn apply_outbound_transport(
    stream: Option<&Value>,
    out: &mut Map<String, Value>,
    index: usize,
) -> Result<()> {
    let network = stream
        .and_then(|s| s.get("network"))
        .and_then(Value::as_str)
        .unwrap_or("tcp");
    match network {
        "tcp" => Ok(()),
        "ws" => {
            let settings = stream.and_then(|s| s.get("wsSettings"));
            let path = settings
                .and_then(|s| s.get("path"))
                .and_then(Value::as_str)
                .unwrap_or("/");
            let host = settings
                .and_then(|s| s.get("headers"))
                .and_then(|h| h.get("Host"))
                .and_then(Value::as_str);
            let mut transport = Map::new();
            transport.insert("type".into(), json!("ws"));
            transport.insert("path".into(), json!(path));
            if let Some(host) = host {
                transport.insert("host".into(), json!(host));
            }
            out.insert("transport".into(), Value::Object(transport));
            Ok(())
        }
        "grpc" => {
            let settings = stream.and_then(|s| s.get("grpcSettings"));
            let service = settings
                .and_then(|s| s.get("serviceName"))
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| anyhow!("出站的 gRPC 缺少 serviceName"))?;
            let multi_mode = settings
                .and_then(|s| s.get("multiMode"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let (single, multi_path) = grpc_paths(service);
            // multiMode 时 Xray 客户端请求的是 `/<service>/TunMulti`，不是单流路径。
            let path = if multi_mode {
                multi_path.ok_or_else(|| {
                    anyhow!("outbounds[{index}] 的 gRPC 使用新式完整路径 + multiMode，但缺少 `单路径|多路径` 分隔")
                })?
            } else {
                single
            };
            let mut transport = Map::new();
            transport.insert("type".into(), json!("grpc"));
            transport.insert("path".into(), json!(path));
            if multi_mode {
                transport.insert("multi".into(), json!(true));
            }
            out.insert("transport".into(), Value::Object(transport));
            Ok(())
        }
        "xhttp" => {
            let settings = stream.and_then(|s| s.get("xhttpSettings"));
            let path = settings
                .and_then(|s| s.get("path"))
                .and_then(Value::as_str)
                .unwrap_or("/");
            let mut transport = Map::new();
            transport.insert("type".into(), json!("xhttp"));
            transport.insert("path".into(), json!(path));
            if let Some(host) = settings.and_then(|s| s.get("host")).and_then(Value::as_str) {
                transport.insert("host".into(), json!(host));
            }
            if let Some(mode) = settings.and_then(|s| s.get("mode")).and_then(Value::as_str) {
                transport.insert("mode".into(), json!(mode));
            }
            if settings
                .and_then(|s| s.get("extra"))
                .and_then(|extra| extra.get("downloadSettings"))
                .is_some()
            {
                bail!("出站的 XHTTP downloadSettings 未实现，转换会改变下行语义");
            }
            out.insert("transport".into(), Value::Object(transport));
            Ok(())
        }
        "httpupgrade" => {
            let settings = stream.and_then(|s| s.get("httpupgradeSettings"));
            let path = settings
                .and_then(|s| s.get("path"))
                .and_then(Value::as_str)
                .unwrap_or("/");
            let mut transport = Map::new();
            transport.insert("type".into(), json!("httpupgrade"));
            transport.insert("path".into(), json!(path));
            if let Some(host) = settings.and_then(|s| s.get("host")).and_then(Value::as_str) {
                transport.insert("host".into(), json!(host));
            }
            out.insert("transport".into(), Value::Object(transport));
            Ok(())
        }
        "kcp" => {
            let mut transport = Map::new();
            transport.insert("type".into(), json!("kcp"));
            out.insert("transport".into(), Value::Object(transport));
            Ok(())
        }
        other => bail!("出站的 network={other} 暂不支持转换"),
    }
}

fn first_vnext(settings: &Value, index: usize) -> Result<(String, &Value)> {
    let vnext = settings
        .get("vnext")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or_else(|| anyhow!("outbounds[{index}] 缺少 vnext"))?;
    let endpoint = server_endpoint(vnext, index)?;
    let user = vnext
        .get("users")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or_else(|| anyhow!("outbounds[{index}] 缺少 users"))?;
    Ok((endpoint, user))
}

fn first_server(settings: &Value, index: usize) -> Result<&Value> {
    settings
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or_else(|| anyhow!("outbounds[{index}] 缺少 servers"))
}

fn server_endpoint(server: &Value, index: usize) -> Result<String> {
    let address =
        string(server, "address").ok_or_else(|| anyhow!("outbounds[{index}] 缺少 address"))?;
    let port = number(server, "port").ok_or_else(|| anyhow!("outbounds[{index}] 缺少 port"))?;
    endpoint(address, port)
}

fn convert_routing(
    value: Option<&Value>,
    outbounds: &[Value],
    report: &mut Report,
) -> Result<Value> {
    // Xray 的默认出站就是**配置里第一个出站**（proxyman 用首个注册的出站做
    // defaultHandler）。按 tag 名猜 proxy/direct 会改变流量路径：一个
    // `[{tag:"node"},{tag:"direct"}]` 的上游配置会被转成默认直连。
    let default = outbounds
        .first()
        .and_then(|item| item.get("tag"))
        .and_then(Value::as_str)
        .unwrap_or("direct");
    report.note(format!(
        "route.default 取 Xray 第一个出站 {default}（Xray 以首个出站为默认出口）"
    ));

    let mut route = Map::new();
    route.insert("default".into(), json!(default));
    let Some(routing) = value else {
        return Ok(Value::Object(route));
    };

    let strategy = routing
        .get("domainStrategy")
        .and_then(Value::as_str)
        .unwrap_or("AsIs");
    let strategy = match strategy {
        "AsIs" => "as-is",
        "IPIfNonMatch" => "ip-if-non-match",
        other => {
            report.note(format!("routing.domainStrategy={other} 按 as-is 处理"));
            "as-is"
        }
    };
    route.insert("domain_strategy".into(), json!(strategy));

    let mut rules = Vec::new();
    if let Some(items) = routing.get("rules").and_then(Value::as_array) {
        for (index, item) in items.iter().enumerate() {
            let Some(outbound) = string(item, "outboundTag") else {
                bail!("routing.rules[{index}] 缺少 outboundTag，转换会改变流量路径");
            };
            if item.get("balancerTag").is_some() {
                bail!("routing.rules[{index}] 使用 balancerTag，暂不支持转换");
            }
            let mut base = Map::new();
            base.insert("outbound".into(), json!(outbound));
            let domain_groups = convert_domains(item.get("domain"), index, report)?;
            if let Some(ips) = item.get("ip").and_then(Value::as_array) {
                let mut cidrs = Vec::new();
                let mut has_private = false;
                let mut has_other_ip = false;
                for ip in ips.iter().filter_map(Value::as_str) {
                    if ip == "geoip:private" {
                        has_private = true;
                        // Xray 的 geoip:private 来自 geoip.dat 预定义标签，其实际地址
                        // 集合未核实；与 sing-box ip_is_private（!IsPublicAddr）可能
                        // 不完全相同，这里做近似映射并提示人工复核。
                        report.note(format!(
                            "routing.rules[{index}] 的 geoip:private 近似映射为 ip_is_private，请复核地址集合差异"
                        ));
                        base.insert("ip_is_private".into(), json!(true));
                    } else if let Some(code) = ip.strip_prefix("geoip:") {
                        has_other_ip = true;
                        // dubhe 的 ip_cidrs 支持 geoip:<code>，同样要求
                        // geo.geoip 指向数据文件。
                        cidrs.push(json!(format!("geoip:{code}")));
                        report.note(format!(
                            "routing.rules[{index}] 的 {ip} 已保留；在 dubhe 配置里设置 geo.geoip 指向 geoip.dat 才会生效"
                        ));
                    } else if ip.starts_with("ext:") {
                        has_other_ip = true;
                        report.note(format!(
                            "routing.rules[{index}] 的 {ip} 需要外部规则集，已跳过；可用 geo.rule_sets 引用 sing-box source JSON"
                        ));
                    } else if ip.starts_with('!') {
                        has_other_ip = true;
                        // Xray 的 `!` 只否定 IP 条件，而 dubhe 的 invert 翻转整条规则；
                        // 两者只在「规则没有其它条件」时才等价，不做有损转换。
                        report.note(format!(
                            "routing.rules[{index}] 的 {ip}（反向 IP 匹配）无法等价表达，已跳过"
                        ));
                    } else {
                        has_other_ip = true;
                        cidrs.push(json!(ip));
                    }
                }
                anyhow::ensure!(
                    !(has_private && has_other_ip),
                    "routing.rules[{index}] 在同一 ip 数组里混用了 geoip:private 与其它项；\
                     Xray 里它们是并集，而 dubhe 的 ip_is_private 与 ip_cidrs 之间是交集，\
                     无法等价转换。请拆成多条规则"
                );
                if !cidrs.is_empty() {
                    base.insert("ip_cidrs".into(), Value::Array(cidrs));
                }
            }
            if let Some(ports) = item.get("port") {
                base.insert("ports".into(), convert_ports(ports)?);
            }
            if let Some(inbound) = item.get("inboundTag").and_then(Value::as_array) {
                let tags: Vec<Value> = inbound
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|v| json!(v))
                    .collect();
                if !tags.is_empty() {
                    base.insert("inbounds".into(), Value::Array(tags));
                }
            }
            if let Some(network) = item.get("network").and_then(Value::as_str) {
                let mut networks = Vec::new();
                for part in network.split(',') {
                    match part.trim() {
                        "tcp" => networks.push(json!("tcp")),
                        "udp" => networks.push(json!("udp")),
                        other => {
                            report.note(format!("routing.rules[{index}] 的 network={other} 已跳过"))
                        }
                    }
                }
                if !networks.is_empty() {
                    base.insert("networks".into(), Value::Array(networks));
                }
            }
            // 只允许把**有匹配条件**的规则写出去。若条件全都被跳过
            // （例如只有 `ext:` 引用），剩下的 `{outbound}` 会变成
            // 无条件规则——把所有流量导向该出站。
            for group in domain_groups {
                let mut rule = base.clone();
                rule.extend(group);
                let has_condition = [
                    "domains",
                    "domain_suffix",
                    "domain_keyword",
                    "domain_regex",
                    "ip_cidrs",
                    "ip_is_private",
                    "ports",
                    "inbounds",
                    "networks",
                ]
                .iter()
                .any(|key| rule.contains_key(*key));
                anyhow::ensure!(
                    has_condition,
                    "routing.rules[{index}] 转换后没有任何匹配条件（引用均被跳过），\
                     继续输出会变成无条件规则；请在 Xray 侧展开或补充具体值"
                );
                rules.push(Value::Object(rule));
            }
        }
    }
    route.insert("rules".into(), Value::Array(rules));
    Ok(Value::Object(route))
}

/// 把 Xray 的 `domain` 数组按种类拆成多组条件。
///
/// Xray 的 `domain` 数组内部是**并集**（`domain:a.com` 或 `keyword:b` 任一命中），
/// 而 dubhe 的 `domains`/`domain_suffix`/`domain_keyword`/`domain_regex` 是不同
/// 字段、彼此取**交集**。直接塞进同一条规则会从 OR 变成 AND：本该走代理的流量
/// 落到默认出口。按种类拆成多条同 outbound 的相邻规则，才保持并集语义。
fn convert_domains(
    value: Option<&Value>,
    index: usize,
    report: &mut Report,
) -> Result<Vec<Map<String, Value>>> {
    let Some(value) = value else {
        return Ok(vec![Map::new()]);
    };
    let domains = value
        .as_array()
        .ok_or_else(|| anyhow!("routing.rules[{index}].domain 必须是数组"))?;
    let mut exact = Vec::new();
    let mut suffix = Vec::new();
    let mut keyword = Vec::new();
    let mut regex = Vec::new();
    for domain in domains.iter().filter_map(Value::as_str) {
        if domain.starts_with("geosite:") {
            // dubhe 支持 geosite:，但要求配置里给出 geo.geosite 数据文件。
            exact.push(json!(domain));
            report.note(format!(
                "routing.rules[{index}] 的 {domain} 已保留；在 dubhe 配置里设置 geo.geosite 指向 geosite.dat 才会生效"
            ));
        } else if domain.starts_with("ext:") {
            report.note(format!(
                "routing.rules[{index}] 的 {domain} 需要外部规则集，已跳过；可用 geo.rule_sets 引用 sing-box source JSON"
            ));
        } else if let Some(item) = domain.strip_prefix("domain:") {
            suffix.push(json!(item));
        } else if let Some(item) = domain.strip_prefix("keyword:") {
            keyword.push(json!(item));
        } else if let Some(item) = domain.strip_prefix("regexp:") {
            regex.push(json!(item));
        } else if let Some(item) = domain.strip_prefix("full:") {
            exact.push(json!(item));
        } else if domain.starts_with("dotless:") {
            report.note(format!(
                "routing.rules[{index}] 的 {domain}（无点域名）暂无对应字段，已跳过"
            ));
        } else {
            exact.push(json!(domain));
        }
    }
    let mut groups = Vec::new();
    for (key, values) in [
        ("domains", exact),
        ("domain_suffix", suffix),
        ("domain_keyword", keyword),
        ("domain_regex", regex),
    ] {
        if values.is_empty() {
            continue;
        }
        let mut group = Map::new();
        group.insert(key.into(), Value::Array(values));
        groups.push(group);
    }
    if groups.is_empty() {
        // 数组里只有被跳过的引用：让调用方的「没有匹配条件」检查处理。
        groups.push(Map::new());
    }
    Ok(groups)
}

fn convert_ports(value: &Value) -> Result<Value> {
    let text = match value {
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        _ => bail!("port 字段必须是数字或字符串"),
    };
    let mut ranges = Vec::new();
    for part in text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start: u16 = start
                .parse()
                .map_err(|_| anyhow!("port 范围无效: {part}"))?;
            let end: u16 = end.parse().map_err(|_| anyhow!("port 范围无效: {part}"))?;
            ranges.push(json!({"start": start, "end": end}));
        } else {
            let port: u16 = part.parse().map_err(|_| anyhow!("port 无效: {part}"))?;
            ranges.push(json!({"start": port, "end": port}));
        }
    }
    Ok(Value::Array(ranges))
}

fn string<'a>(object: &'a Value, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn number(object: &Value, key: &str) -> Option<u16> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
}

fn string_array(object: &Value, key: &str) -> Vec<String> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// `host` 与 `port` 拼成 `HOST:PORT`；IPv6 自动加方括号。
fn endpoint(host: &str, port: u16) -> Result<String> {
    let host = host.trim();
    let host = if host.is_empty() { "0.0.0.0" } else { host };
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

/// 拆 `host:port` 或 `[v6]:port`。
fn split_endpoint(value: &str) -> Result<(String, u16)> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("端点缺少端口: {value}"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().map_err(|_| anyhow!("端点端口无效: {value}"))?;
    if host.is_empty() {
        bail!("端点缺少主机: {value}");
    }
    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xray_config() -> serde_json::Value {
        serde_json::json!({
            "inbounds": [
                {
                    "tag": "vless-reality",
                    "listen": "0.0.0.0",
                    "port": 443,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "alice", "flow": "xtls-rprx-vision"}],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "dest": "www.example.com:443",
                            "serverNames": ["www.example.com"],
                            "privateKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                            "shortIds": ["ab"]
                        }
                    }
                },
                {
                    "tag": "trojan-tls",
                    "port": 8443,
                    "protocol": "trojan",
                    "settings": {"clients": [{"password": "pw", "email": "bob"}]},
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {"certificates": [{"certificateFile": "/c.pem", "keyFile": "/k.pem"}]}
                    }
                },
                {
                    "tag": "ss",
                    "port": 8388,
                    "protocol": "shadowsocks",
                    "settings": {"method": "aes-256-gcm", "password": "sspw"}
                }
            ],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"}
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {"type": "field", "domain": ["domain:example.org", "keyword:ads", "full:exact.example"], "outboundTag": "direct"},
                    {"type": "field", "ip": ["10.0.0.0/8"], "port": "53,80-90", "outboundTag": "block"},
                    // geosite 单独一条：与 domain:/keyword: 混写无法等价转换。
                    {"type": "field", "domain": ["geosite:google"], "outboundTag": "block"}
                ]
            }
        })
    }

    #[test]
    fn converts_reality_trojan_and_shadowsocks_inbounds() {
        let text = xray_config().to_string();
        let converted = from_xray(&text, None).expect("应可转换");
        let (config, report) = (converted.config, converted.report);
        let rendered = serde_json::to_value(&config).unwrap();
        let inbounds = rendered["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 3);
        assert_eq!(inbounds[0]["type"], "vless-reality");
        assert_eq!(inbounds[0]["listen"], "0.0.0.0:443");
        assert_eq!(inbounds[0]["users"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(inbounds[1]["type"], "trojan");
        assert_eq!(inbounds[1]["certificate"], "/c.pem");
        assert_eq!(inbounds[2]["type"], "shadowsocks");
        assert_eq!(inbounds[2]["method"], "aes-256-gcm");
        // geosite 已保留，必须在报告里提示需要配置 geo.geosite。
        assert!(report.notes.iter().any(|note| note.contains("geo.geosite")));
    }

    #[test]
    fn converts_static_routing() {
        let text = xray_config().to_string();
        let converted = from_xray(&text, None).expect("应可转换");
        let config = converted.config;
        let rendered = serde_json::to_value(&config).unwrap();
        let route = &rendered["route"];
        assert_eq!(route["default"], "direct");
        assert_eq!(route["domain_strategy"], "ip-if-non-match");
        let rules = route["rules"].as_array().unwrap();
        // Xray 的 domain 数组是并集，dubhe 的不同字段是交集：转换器必须按种类
        // 拆成多条同 outbound 的规则，否则 domain:/keyword: 从 OR 变成 AND。
        assert!(
            rules
                .iter()
                .any(|rule| rule["outbound"] == "direct"
                    && rule["domain_suffix"][0] == "example.org"),
            "{rules:?}"
        );
        assert!(
            rules
                .iter()
                .any(|rule| rule["outbound"] == "direct" && rule["domain_keyword"][0] == "ads"),
            "{rules:?}"
        );
        // `full:` 必须进 domains（此前会被 geosite 分支覆盖掉）。
        assert!(
            rules.iter().any(|rule| {
                rule["domains"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|item| item == "exact.example"))
            }),
            "domains 应保留 full:exact.example：{rules:?}"
        );
        // geosite 引用必须保留在 domains 里（此前被后续 insert 覆盖）。
        assert!(
            rules.iter().any(|rule| {
                rule["domains"]
                    .as_array()
                    .is_some_and(|items| items.iter().any(|item| item == "geosite:google"))
            }),
            "domains 应保留 geosite:google：{rules:?}"
        );
        let ports = rules
            .iter()
            .find(|rule| rule["outbound"] == "block" && rule.get("ports").is_some())
            .expect("端口规则应存在");
        assert_eq!(ports["ports"][0]["start"], 53);
        assert_eq!(ports["ports"][1]["start"], 80);
        assert_eq!(ports["ports"][1]["end"], 90);
    }

    /// `geoip:<code>` 必须保留到 `ip_cidrs`，而不是「提示后跳过」——
    /// 跳过会让整条规则退化成无条件匹配。
    #[test]
    fn keeps_geoip_reference_in_ip_cidrs() {
        let value = serde_json::json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [
                {"type": "field", "ip": ["geoip:cn", "10.0.0.0/8"], "outboundTag": "direct"}
            ]}
        });
        let converted = from_xray(&value.to_string(), None).expect("应可转换");
        let rendered = serde_json::to_value(&converted.config).unwrap();
        let cidrs = rendered["route"]["rules"][0]["ip_cidrs"]
            .as_array()
            .expect("ip_cidrs 应存在");
        let values: Vec<&str> = cidrs.iter().filter_map(|item| item.as_str()).collect();
        assert!(values.contains(&"geoip:cn"), "应保留 geoip:cn：{values:?}");
        assert!(
            converted
                .report
                .notes
                .iter()
                .any(|note| note.contains("geo.geoip"))
        );
    }

    #[test]
    fn outbound_tls_requires_explicit_ca_file() {
        let value = serde_json::json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{"address": "example.com", "port": 443, "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},
                "streamSettings": {"network": "tcp", "security": "tls"}
            }]
        });
        let error = from_xray(&value.to_string(), None).unwrap_err();
        assert!(error.to_string().contains("--ca-file"));
        let converted = from_xray(&value.to_string(), Some("/etc/ssl/certs/ca.pem"))
            .expect("给出信任锚后应可转换");
        let config = converted.config;
        let rendered = serde_json::to_value(&config).unwrap();
        assert_eq!(
            rendered["outbounds"][0]["tls"]["ca_file"],
            "/etc/ssl/certs/ca.pem"
        );
    }

    #[test]
    fn unsupported_network_is_an_error_not_a_silent_drop() {
        let value = serde_json::json!({
            "inbounds": [{
                "port": 443,
                "protocol": "vless",
                "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]},
                "streamSettings": {"network": "quic", "security": "none"}
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        });
        let error = from_xray(&value.to_string(), None).unwrap_err();
        assert!(error.to_string().contains("quic"), "{error}");
    }

    /// Xray 对 socks/http/shadowsocks 出站同样套用 `streamSettings`。此前转换器
    /// 只在这些协议之外处理 TLS，带 TLS 的上游被静默降成明文，退出码仍是 0。
    #[test]
    fn proxy_outbound_tls_is_not_dropped() {
        let value = serde_json::json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [
                {
                    "tag": "socks-tls",
                    "protocol": "socks",
                    "settings": {"servers": [{
                        "address": "127.0.0.2", "port": 1080,
                        "users": [{"user": "u", "pass": "p"}]
                    }]},
                    "streamSettings": {
                        "network": "tcp", "security": "tls",
                        "tlsSettings": {"serverName": "proxy.example"}
                    }
                },
                {
                    "tag": "http-tls",
                    "protocol": "http",
                    "settings": {"servers": [{"address": "127.0.0.3", "port": 3128}]},
                    "streamSettings": {"network": "tcp", "security": "tls"}
                }
            ]
        });
        // 必须要求信任锚，而不是生成一份明文上游。
        let error = from_xray(&value.to_string(), None).unwrap_err();
        assert!(error.to_string().contains("--ca-file"), "{error}");

        let converted = from_xray(&value.to_string(), Some("/etc/ssl/certs/ca.pem"))
            .expect("给出信任锚后应可转换");
        let rendered = serde_json::to_value(&converted.config).unwrap();
        let outbounds = rendered["outbounds"].as_array().unwrap();
        assert_eq!(outbounds[0]["tls"]["ca_file"], "/etc/ssl/certs/ca.pem");
        assert_eq!(outbounds[0]["tls"]["server_name"], "proxy.example");
        assert_eq!(outbounds[1]["tls"]["ca_file"], "/etc/ssl/certs/ca.pem");
        assert_eq!(outbounds[1]["username"], serde_json::Value::Null);
    }

    /// dubhe 的 shadowsocks 出站不支持 TLS；不能静默丢掉。
    #[test]
    fn shadowsocks_outbound_tls_fails_closed() {
        let value = serde_json::json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [{
                "tag": "ss-tls",
                "protocol": "shadowsocks",
                "settings": {"servers": [{
                    "address": "127.0.0.3", "port": 8388,
                    "method": "aes-256-gcm", "password": "pw"
                }]},
                "streamSettings": {"network": "tcp", "security": "tls"}
            }]
        });
        let error = from_xray(&value.to_string(), Some("/etc/ssl/certs/ca.pem")).unwrap_err();
        assert!(error.to_string().contains("不支持 TLS"), "{error}");
    }

    /// dubhe 的 socks/http/shadowsocks 出站只支持原始 TCP，承载无法等价表达时
    /// 必须报错——否则同样是「成功生成一份明文配置」。
    #[test]
    fn proxy_outbound_with_transport_fails_instead_of_becoming_plain() {
        let value = serde_json::json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [{
                "tag": "socks-ws",
                "protocol": "socks",
                "settings": {"servers": [{"address": "127.0.0.2", "port": 1080}]},
                "streamSettings": {"network": "ws", "security": "tls"}
            }]
        });
        let error = from_xray(&value.to_string(), Some("/etc/ssl/certs/ca.pem")).unwrap_err();
        assert!(error.to_string().contains("network=ws"), "{error}");
    }

    #[test]
    fn dialer_proxy_chain_fails_closed() {
        let value = serde_json::json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [{
                "tag": "chained",
                "protocol": "socks",
                "settings": {"servers": [{"address": "127.0.0.2", "port": 1080}]},
                "streamSettings": {"sockopt": {"dialerProxy": "hop"}}
            }]
        });
        let error = from_xray(&value.to_string(), None).unwrap_err();
        assert!(error.to_string().contains("dialerProxy"), "{error}");
    }

    /// Xray 的默认出站是**配置里第一个出站**；按 tag 名猜会改变流量路径。
    #[test]
    fn default_outbound_is_the_first_one_like_xray() {
        let value = serde_json::json!({
            "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [
                {
                    "tag": "node",
                    "protocol": "socks",
                    "settings": {"servers": [{"address": "127.0.0.2", "port": 1080}]}
                },
                {"tag": "direct", "protocol": "freedom"}
            ]
        });
        let converted = from_xray(&value.to_string(), None).expect("应可转换");
        let rendered = serde_json::to_value(&converted.config).unwrap();
        assert_eq!(
            rendered["route"]["default"], "node",
            "默认出口必须跟随 Xray 的首个出站"
        );
    }

    /// Xray 的 `domain` 数组内部是并集；转成 dubhe 的不同字段后必须仍然是并集。
    #[test]
    fn mixed_domain_kinds_stay_a_union() {
        use crate::session::{Host, Network, Target};

        let value = serde_json::json!({
            "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [
                {
                    "tag": "node",
                    "protocol": "socks",
                    "settings": {"servers": [{"address": "127.0.0.2", "port": 1080}]}
                },
                {"tag": "direct", "protocol": "freedom"}
            ],
            "routing": {"rules": [{
                "type": "field",
                "domain": ["domain:ads.example", "keyword:tracker"],
                "outboundTag": "direct"
            }]}
        });
        let converted = from_xray(&value.to_string(), None).expect("应可转换");
        let router = crate::route::Router::new(&converted.config).expect("路由应可编译");
        let select = |host: &str| {
            router.select(
                "in",
                Network::Tcp,
                &Target {
                    host: Host::Domain(host.into()),
                    port: 443,
                },
            )
        };
        // 两种写法都必须命中 direct；未命中的域名回落到首个出站（node）。
        assert_eq!(select("x.ads.example"), crate::config::OutboundKind::Direct);
        assert_eq!(
            select("cdn.tracker.example"),
            crate::config::OutboundKind::Direct
        );
        assert_ne!(select("other.example"), crate::config::OutboundKind::Direct);
    }

    #[test]
    fn routing_rule_without_outbound_tag_fails_closed() {
        let value = serde_json::json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [{"type": "field", "domain": ["example.com"]}]}
        });
        let error = from_xray(&value.to_string(), None).unwrap_err();
        assert!(error.to_string().contains("outboundTag"));
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;

    fn config_with(stream: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "inbounds": [{
                "tag": "in",
                "listen": "0.0.0.0",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "alice"}],
                    "decryption": "none"
                },
                "streamSettings": stream
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        })
    }

    fn certs() -> serde_json::Value {
        serde_json::json!({
            "security": "tls",
            "tlsSettings": {"certificates": [{"certificateFile": "/c.pem", "keyFile": "/k.pem"}]}
        })
    }

    fn convert_inbound(stream: serde_json::Value) -> serde_json::Value {
        let text = config_with(stream).to_string();
        let converted = from_xray(&text, None).expect("应可转换");
        serde_json::to_value(&converted.json).unwrap()["inbounds"][0].clone()
    }

    /// Xray 的 serviceName 是服务名，客户端请求 `/<service>/Tun`；本仓库存完整
    /// 路径。此前只拼了 `/<service>`，转换出的入口会 404。
    #[test]
    fn grpc_inbound_appends_the_stream_name() {
        let mut stream = certs();
        stream["network"] = json!("grpc");
        stream["grpcSettings"] = json!({"serviceName": "GunService"});
        let inbound = convert_inbound(stream);
        assert_eq!(inbound["type"], "vless-grpc");
        assert_eq!(inbound["grpc"]["path"], "/GunService/Tun");
        assert!(inbound["grpc"].get("multi_path").is_none());

        let mut stream = certs();
        stream["network"] = json!("grpc");
        stream["grpcSettings"] = json!({"serviceName": "GunService", "multiMode": true});
        let inbound = convert_inbound(stream);
        assert_eq!(inbound["grpc"]["path"], "/GunService/Tun");
        assert_eq!(inbound["grpc"]["multi_path"], "/GunService/TunMulti");
    }

    /// 新式写法：Xray 把以 `/` 开头的 serviceName 当完整路径，`单|多` 分隔。
    #[test]
    fn grpc_inbound_accepts_full_path_service_name() {
        let mut stream = certs();
        stream["network"] = json!("grpc");
        stream["grpcSettings"] = json!({"serviceName": "/svc/a|svc/b", "multiMode": true});
        let inbound = convert_inbound(stream);
        assert_eq!(inbound["grpc"]["path"], "/svc/a");
        assert_eq!(inbound["grpc"]["multi_path"], "/svc/b");
    }

    #[test]
    fn xhttp_inbound_converts_path_and_host() {
        let mut stream = certs();
        stream["network"] = json!("xhttp");
        stream["xhttpSettings"] = json!({"path": "/x", "host": "cdn.example", "mode": "packet-up"});
        let inbound = convert_inbound(stream);
        assert_eq!(inbound["type"], "vless-xhttp");
        assert_eq!(inbound["xhttp"]["path"], "/x");
        assert_eq!(inbound["xhttp"]["host"], "cdn.example");
        assert_eq!(inbound["xhttp"]["mode"], "packet-up");
    }

    #[test]
    fn xhttp_download_settings_are_rejected() {
        let mut stream = certs();
        stream["network"] = json!("xhttp");
        stream["xhttpSettings"] = json!({
            "path": "/x",
            "extra": {"downloadSettings": {"path": "/down"}}
        });
        let text = config_with(stream).to_string();
        let error = from_xray(&text, None).unwrap_err();
        assert!(error.to_string().contains("downloadSettings"), "{error}");
    }

    #[test]
    fn httpupgrade_inbound_converts_path_and_host() {
        let mut stream = certs();
        stream["network"] = json!("httpupgrade");
        stream["httpupgradeSettings"] = json!({"path": "/up", "host": "h.example"});
        let inbound = convert_inbound(stream);
        assert_eq!(inbound["type"], "vless-httpupgrade");
        assert_eq!(inbound["httpupgrade"]["path"], "/up");
        assert_eq!(inbound["httpupgrade"]["host"], "h.example");
    }

    #[test]
    fn kcp_inbound_converts_without_tls() {
        let mut stream = serde_json::json!({"network": "kcp", "security": "none"});
        // mKCP 自带加密层，不与 TLS 组合；转换器应为无 TLS 的 kcp 生成 vless-kcp。
        stream["security"] = json!("none");
        let inbound = convert_inbound(stream);
        assert_eq!(inbound["type"], "vless-kcp");
        assert!(inbound.get("certificate").is_none(), "{inbound}");
    }

    #[test]
    fn kcp_with_tls_is_rejected() {
        let mut stream = certs();
        stream["network"] = json!("kcp");
        let text = config_with(stream).to_string();
        let error = from_xray(&text, None).unwrap_err();
        assert!(error.to_string().contains("kcp"), "{error}");
    }

    #[test]
    fn kcp_inbound_does_not_require_allow_insecure() {
        // mKCP 自带认证层；转换结果不应因缺少 allow_insecure_transport 而被拒。
        let stream = serde_json::json!({"network": "kcp", "security": "none"});
        let inbound = convert_inbound(stream);
        assert_eq!(inbound["type"], "vless-kcp");
    }

    #[test]
    fn outbound_grpc_transport_converts() {
        let value = serde_json::json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "example.com",
                    "port": 443,
                    "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]
                }]},
                "streamSettings": {
                    "network": "grpc",
                    "security": "tls",
                    "grpcSettings": {"serviceName": "Tun", "multiMode": true}
                }
            }]
        });
        let converted = from_xray(&value.to_string(), Some("/ca.pem")).expect("应可转换");
        let json = serde_json::to_value(&converted.json).unwrap();
        let outbound = &json["outbounds"][0];
        assert_eq!(outbound["transport"]["type"], "grpc");
        // multiMode 时 Xray 客户端请求 `/<service>/TunMulti`。
        assert_eq!(outbound["transport"]["path"], "/Tun/TunMulti");
        assert_eq!(outbound["transport"]["multi"], true);
        assert_eq!(outbound["tls"]["ca_file"], "/ca.pem");
    }
}

#[cfg(test)]
mod routing_field_alignment_tests {
    use super::from_xray;

    fn convert(rules: serde_json::Value) -> (serde_json::Value, String) {
        let text = serde_json::json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"}
            ],
            "routing": {"rules": rules}
        })
        .to_string();
        let converted = from_xray(&text, None).expect("应可转换");
        let report = converted.report.notes.join("\n");
        (converted.json, report)
    }

    #[test]
    fn geoip_private_becomes_ip_is_private_with_a_review_note() {
        // 近似映射：Xray 的 geoip:private 实际集合未核实，必须提示复核。
        let (value, report) = convert(serde_json::json!([
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}
        ]));
        assert_eq!(value["route"]["rules"][0]["ip_is_private"], true);
        assert!(report.contains("复核"), "应提示复核地址集合: {report}");
    }

    #[test]
    fn regexp_prefix_becomes_domain_regex() {
        let (value, _) = convert(serde_json::json!([
            {"type": "field", "domain": ["regexp:^stun\\..+"], "outboundTag": "direct"}
        ]));
        assert_eq!(value["route"]["rules"][0]["domain_regex"][0], "^stun\\..+");
    }

    #[test]
    fn full_prefix_becomes_exact_domain() {
        let (value, _) = convert(serde_json::json!([
            {"type": "field", "domain": ["full:xray.com"], "outboundTag": "direct"}
        ]));
        assert_eq!(value["route"]["rules"][0]["domains"][0], "xray.com");
    }

    #[test]
    fn negated_ip_is_reported_instead_of_lossy_invert() {
        // Xray 的 `!` 只否定 IP 条件，整条规则 invert 会改变语义。
        // 加一个 port 条件，使这条规则在丢弃 IP 后仍有匹配条件
        // （只剩被丢弃引用的规则现在会直接报错，见下一条用例）。
        let (value, report) = convert(serde_json::json!([
            {"type": "field", "ip": ["!geoip:cn"], "port": "443", "outboundTag": "direct"}
        ]));
        assert!(value["route"]["rules"][0].get("invert").is_none());
        assert!(value["route"]["rules"][0].get("ip_cidrs").is_none());
        assert!(report.contains("反向 IP 匹配"), "{report}");
    }

    /// 规则的所有条件都被跳过时必须报错：只剩 `{outbound}` 会变成
    /// 无条件规则，把所有流量导向该出站。
    #[test]
    fn rule_with_only_dropped_references_is_rejected() {
        let text = serde_json::json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [
                {"type": "field", "domain": ["ext:my.dat:google"], "outboundTag": "direct"}
            ]}
        })
        .to_string();
        let error = from_xray(&text, None).unwrap_err().to_string();
        assert!(
            error.contains("没有任何匹配条件"),
            "应拒绝无条件规则：{error}"
        );
    }

    /// 同一 domain 数组混用 geosite 与 domain:/keyword:/regexp: 时，按种类拆成
    /// 多条同 outbound 的规则——Xray 是并集，直接塞进同一条会变成交集。
    #[test]
    fn mixed_geosite_and_suffix_in_one_array_is_split() {
        let text = serde_json::json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [
                {"type": "field", "domain": ["domain:a.test", "geosite:google"],
                 "outboundTag": "direct"}
            ]}
        })
        .to_string();
        let converted = from_xray(&text, None).expect("应拆成两条规则");
        let rendered = serde_json::to_value(&converted.config).unwrap();
        let rules = rendered["route"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2, "{rules:?}");
        assert_eq!(rules[0]["domains"][0], "geosite:google");
        assert_eq!(rules[1]["domain_suffix"][0], "a.test");
    }

    /// geoip:private 与其它 IP 项混写同样无法等价转换。
    #[test]
    fn mixed_private_and_geoip_is_rejected() {
        let text = serde_json::json!({
            "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks"}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [
                {"type": "field", "ip": ["geoip:private", "geoip:cn"], "outboundTag": "direct"}
            ]}
        })
        .to_string();
        let error = from_xray(&text, None).unwrap_err().to_string();
        assert!(error.contains("geoip:private"), "{error}");
    }

    #[test]
    fn negated_ip_mixed_with_positive_is_also_reported() {
        let (_, report) = convert(serde_json::json!([
            {"type": "field", "ip": ["!geoip:cn", "geoip:telegram"], "outboundTag": "direct"}
        ]));
        assert!(report.contains("反向 IP 匹配"), "{report}");
    }
}
