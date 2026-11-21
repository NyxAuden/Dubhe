//! NW3（Nowhere Protocol v3）Portal 适配。
//!
//! 协议线格式、TLS/QUIC 承载与转发逻辑直接复用 Nowhere 3.3.0（GPL-3.0-only）；
//! 本模块只负责把本内核的 [`Inbound::Nw3`] 配置翻译成 Portal URL 并构造驱动。

use std::{io, net::SocketAddr, path::Path};

use url::Url;

use crate::config::{Config, Inbound, Nw3Egress, Nw3Out};

/// 构造 Portal URL：`portal://KEY@ENDPOINT?tls=..&morph=..&out=..`。
///
/// `ENDPOINT` 的同一个端口同时承载 TCP（TLS 1.3）与 QUIC。配置了真实证书时使用
/// `tls=2&crt=..&key=..`；否则使用 Nowhere 的 `tls=1`，由 Portal 在启动时生成
/// 一次性自签名证书（客户端以共享密钥与 Morph 认证，不做 CA 校验）。
// URL 参数直接对应 Nowhere 的查询项；合并成结构体会在调用点重复拼装。
#[allow(clippy::too_many_arguments)]
pub(crate) fn portal_url(
    listen: SocketAddr,
    key: &str,
    morph: bool,
    out: &Nw3Out,
    dial: Option<&str>,
    dial4: Option<&str>,
    dial6: Option<&str>,
    rate: Option<u32>,
    etar: Option<u32>,
    certificate: Option<&Path>,
    private_key: Option<&Path>,
) -> io::Result<Url> {
    let mut query = String::new();
    match (certificate, private_key) {
        (Some(certificate), Some(private_key)) => {
            push_query(&mut query, "tls", "2");
            push_query(&mut query, "crt", &certificate.to_string_lossy());
            push_query(&mut query, "key", &private_key.to_string_lossy());
        }
        _ => push_query(&mut query, "tls", "1"),
    }
    push_query(&mut query, "morph", if morph { "1" } else { "0" });
    push_query(&mut query, "out", out.as_str());
    for (name, value) in [("dial", dial), ("dial4", dial4), ("dial6", dial6)] {
        if let Some(value) = value {
            push_query(&mut query, name, value);
        }
    }
    for (name, value) in [("rate", rate), ("etar", etar)] {
        if let Some(value) = value {
            push_query(&mut query, name, &value.to_string());
        }
    }
    Url::parse(&format!("portal://{key}@{listen}?{query}"))
        .map_err(|error| io::Error::other(format!("NW3 Portal URL 无效: {error}")))
}

/// 追加一个查询参数。
///
/// 不使用 `form_urlencoded`：它把空格编码成 `+`，而 Nowhere 的解码器只处理
/// `%XX`，会把 `+` 当成字面量。这里统一编码成 `%20`，并保留 SOCKS 端点需要的
/// `:`、`@`、`[`、`]` 与既有 `%XX` 转义。
fn push_query(query: &mut String, name: &str, value: &str) {
    if !query.is_empty() {
        query.push('&');
    }
    query.push_str(name);
    query.push('=');
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        // 保留调用方已经写好的 %XX 转义；单独的 % 编码成 %25。
        if byte == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            query.push('%');
        } else if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~' | b':' | b'@' | b'[' | b']')
        {
            query.push(char::from(byte));
        } else {
            query.push_str(&format!("%{byte:02X}"));
        }
        index += 1;
    }
}

/// 由入站配置构造 Portal；失败说明密钥、证书或端点不满足 Nowhere 的要求。
pub(crate) fn prepare(inbound: &Inbound) -> io::Result<nowhere::Portal> {
    let Inbound::Nw3 {
        tag,
        listen,
        key,
        morph,
        out,
        dial,
        dial4,
        dial6,
        rate,
        etar,
        certificate,
        private_key,
        ..
    } = inbound
    else {
        return Err(io::Error::other("非 NW3 入站不能构造 Portal"));
    };
    let url = portal_url(
        *listen,
        key,
        *morph,
        out,
        dial.as_deref(),
        dial4.as_deref(),
        dial6.as_deref(),
        *rate,
        *etar,
        certificate.as_deref(),
        private_key.as_deref(),
    )?;
    nowhere::Portal::new(url, nowhere::Logger)
        .map_err(|error| io::Error::other(format!("入口 {tag} NW3 配置无效: {error:#}")))
}

/// 构造 Egress URL：`egress://KEY@ENDPOINT?morph=..&...`。
///
/// 端点沿用 Nowhere 语法：`host:port` 走 QUIC，`host/tcp:port` 走 TLS，
/// `host/udp:port` 走 QUIC。所有选项都由 Nowhere 的客户端配置解析器校验。
pub(crate) fn egress_url(egress: &Nw3Egress) -> io::Result<Url> {
    let mut query = String::new();
    push_query(&mut query, "morph", if egress.morph { "1" } else { "0" });
    for (name, value) in [
        ("sni", egress.sni.as_deref()),
        ("pin", egress.pin.as_deref()),
        ("dial", egress.dial.as_deref()),
        ("dial4", egress.dial4.as_deref()),
        ("dial6", egress.dial6.as_deref()),
    ] {
        if let Some(value) = value {
            push_query(&mut query, name, value);
        }
    }
    for (name, value) in [("rate", egress.rate), ("etar", egress.etar)] {
        push_query(&mut query, name, &value.unwrap_or(0).to_string());
    }
    Url::parse(&format!(
        "egress://{}@{}?{query}",
        egress.key, egress.endpoint
    ))
    .map_err(|error| io::Error::other(format!("NW3 Egress URL 无效: {error}")))
}

/// 由顶层 `nw3_egress` 配置构造 Egress；失败说明端点、密钥或 TLS 选项无效。
pub(crate) fn prepare_egress(config: &Config) -> io::Result<(String, nowhere::Egress)> {
    let Some(egress) = config.nw3_egress.as_ref() else {
        return Err(io::Error::other("缺少 NW3 Egress 配置"));
    };
    let url = egress_url(egress)?;
    let tag = egress.tag.clone();
    let prepared = nowhere::Egress::new(url, nowhere::Logger)
        .map_err(|error| io::Error::other(format!("{tag} NW3 Egress 配置无效: {error:#}")))?;
    Ok((tag, prepared))
}

/// 运行 Egress 直到外部停止令牌取消；由服务自行维护与 Portal 的连接。
pub(crate) async fn serve_egress(
    egress: nowhere::Egress,
    stop: tokio_util::sync::CancellationToken,
) -> io::Result<()> {
    egress
        .run_with_stop(stop)
        .await
        .map_err(|error| io::Error::other(format!("NW3 Egress 退出: {error:#}")))
}

/// 运行 Portal 直到外部停止令牌取消；Portal 自行绑定同端口的 TCP 与 UDP。
pub(crate) async fn serve(
    portal: nowhere::Portal,
    stop: tokio_util::sync::CancellationToken,
) -> io::Result<()> {
    portal
        .run_with_stop(stop)
        .await
        .map_err(|error| io::Error::other(format!("NW3 Portal 退出: {error:#}")))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const KEY: &str = "0123456789abcdef0123456789abcdef";

    fn query(url: &Url) -> HashMap<String, String> {
        url.query_pairs().into_owned().collect()
    }

    #[test]
    fn egress_url_keeps_carrier_path_and_options() {
        let egress = Nw3Egress {
            tag: "exit".into(),
            endpoint: "example.com/tcp:443".into(),
            key: KEY.into(),
            sni: Some("example.com".into()),
            pin: None,
            morph: false,
            dial: Some("auto".into()),
            dial4: None,
            dial6: None,
            rate: Some(10),
            etar: None,
        };
        let url = egress_url(&egress).unwrap();
        assert_eq!(url.scheme(), "egress");
        assert_eq!(url.username(), KEY);
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.path(), "/tcp:443");
        let query = query(&url);
        assert_eq!(query.get("morph").map(String::as_str), Some("0"));
        assert_eq!(query.get("sni").map(String::as_str), Some("example.com"));
        assert_eq!(query.get("dial").map(String::as_str), Some("auto"));
        assert_eq!(query.get("rate").map(String::as_str), Some("10"));
        assert_eq!(query.get("etar").map(String::as_str), Some("0"));
        assert!(!query.contains_key("pin"));
        assert!(!query.contains_key("dial4"));
    }

    fn direct_portal_url(morph: bool, certificate: Option<&Path>, key: Option<&Path>) -> Url {
        portal_url(
            "127.0.0.1:2000".parse().unwrap(),
            KEY,
            morph,
            &Nw3Out::Direct,
            None,
            None,
            None,
            None,
            None,
            certificate,
            key,
        )
        .unwrap()
    }

    #[test]
    fn self_signed_mode_is_used_without_certificate() {
        let url = direct_portal_url(true, None, None);
        assert_eq!(url.scheme(), "portal");
        assert_eq!(url.username(), KEY);
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert_eq!(url.port(), Some(2000));
        let query = query(&url);
        assert_eq!(query.get("tls").map(String::as_str), Some("1"));
        assert_eq!(query.get("morph").map(String::as_str), Some("1"));
        assert_eq!(query.get("out").map(String::as_str), Some("direct"));
        assert!(!query.contains_key("crt"));
        assert!(!query.contains_key("key"));
    }

    #[test]
    fn egress_out_is_selected_explicitly() {
        let url = portal_url(
            "127.0.0.1:2000".parse().unwrap(),
            KEY,
            true,
            &Nw3Out::Egress,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(query(&url).get("out").map(String::as_str), Some("egress"));
    }

    #[test]
    fn socks_out_and_dial_options_are_passed_through() {
        let out = Nw3Out::Socks("alice:s3cret@[::1]:1080".into());
        let url = portal_url(
            "127.0.0.1:2000".parse().unwrap(),
            KEY,
            true,
            &out,
            None,
            Some("192.0.2.1"),
            None,
            Some(5),
            Some(7),
            None,
            None,
        )
        .unwrap();
        let query = query(&url);
        assert_eq!(
            query.get("out").map(String::as_str),
            Some("alice:s3cret@[::1]:1080")
        );
        assert_eq!(query.get("dial4").map(String::as_str), Some("192.0.2.1"));
        assert_eq!(query.get("rate").map(String::as_str), Some("5"));
        assert_eq!(query.get("etar").map(String::as_str), Some("7"));
        assert!(!query.contains_key("dial"));
    }

    #[test]
    fn socks_out_debug_output_never_leaks_credentials() {
        let out = Nw3Out::Socks("alice:s3cret@127.0.0.1:1080".into());
        let debug = format!("{out:?}");
        assert_eq!(debug, "socks");
        assert!(!debug.contains("alice") && !debug.contains("s3cret"));
    }

    #[test]
    fn certificate_paths_are_encoded_and_decoded_intact() {
        let url = direct_portal_url(
            false,
            Some(Path::new("/etc/ssl/a b/cert.pem")),
            Some(Path::new("/etc/ssl/a b/key.pem")),
        );
        let query = query(&url);
        assert_eq!(query.get("tls").map(String::as_str), Some("2"));
        assert_eq!(query.get("morph").map(String::as_str), Some("0"));
        assert_eq!(
            query.get("crt").map(String::as_str),
            Some("/etc/ssl/a b/cert.pem")
        );
        assert_eq!(
            query.get("key").map(String::as_str),
            Some("/etc/ssl/a b/key.pem")
        );
    }
}
