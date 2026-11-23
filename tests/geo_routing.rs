//! 地理数据集（`geosite:` / `geoip:` / `mmdb:` / `rule_set:`）语义与接线。
//!
//! **语义断言走 Router 选路结果**：`stats.rejected` 对 SOCKS 入口而言任何
//! handler 错误都会加一（包括拨号失败、DNS 失败），无法区分「规则拒绝」与
//! 「连接失败」。用选路结果才确定。
//!
//! 数据集全部由测试现场生成（按 Xray proto 手写 protobuf、按 sing-box
//! rule-set source 格式写 JSON），另有 4 项用真实数据集（缺失时跳过）。

mod common;

use common::{Echo, Running, socks_config};
use dubhe::{
    config::OutboundKind,
    route::Router,
    session::{Host, Network, Target},
};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 按 Xray `xray.common.geodata.GeoSiteList` 编码最小 geosite.dat。
///
/// 手写编码而不是复用生产代码的 prost 结构：测试自证会让实现错误被抵消。
type SiteEntries<'a> = &'a [(&'a str, &'a [(&'a str, u8)])];

fn encode_geosite(entries: SiteEntries<'_>) -> Vec<u8> {
    fn varint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }
    fn bytes_field(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
        varint(out, u64::from(tag << 3 | 2));
        varint(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }
    fn varint_field(out: &mut Vec<u8>, tag: u8, value: u64) {
        varint(out, u64::from(tag << 3));
        varint(out, value);
    }

    let mut list = Vec::new();
    for (code, domains) in entries {
        let mut site = Vec::new();
        bytes_field(&mut site, 1, code.as_bytes());
        for (value, kind) in *domains {
            let mut domain = Vec::new();
            varint_field(&mut domain, 1, u64::from(*kind));
            bytes_field(&mut domain, 2, value.as_bytes());
            bytes_field(&mut site, 2, &domain);
        }
        bytes_field(&mut list, 1, &site);
    }
    list
}

/// 按 `GeoIPList` 编码最小 geoip.dat。
type IpEntries<'a> = &'a [(&'a str, &'a [([u8; 4], u32)])];

fn encode_geoip(entries: IpEntries<'_>) -> Vec<u8> {
    fn varint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }
    fn bytes_field(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
        varint(out, u64::from(tag << 3 | 2));
        varint(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }
    fn varint_field(out: &mut Vec<u8>, tag: u8, value: u64) {
        varint(out, u64::from(tag << 3));
        varint(out, value);
    }

    let mut list = Vec::new();
    for (code, cidrs) in entries {
        let mut entry = Vec::new();
        bytes_field(&mut entry, 1, code.as_bytes());
        for (octets, prefix) in *cidrs {
            let mut cidr = Vec::new();
            bytes_field(&mut cidr, 1, octets);
            varint_field(&mut cidr, 2, u64::from(*prefix));
            bytes_field(&mut entry, 2, &cidr);
        }
        bytes_field(&mut list, 1, &entry);
    }
    list
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> String {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path.display().to_string()
}

fn config(geo: Value, rule: Value) -> Value {
    let mut value = socks_config();
    value["geo"] = geo;
    value["route"] = json!({"default": "direct", "rules": [rule]});
    value
}

/// 用 Router 直接求选路结果，不走网络。
fn select(geo: Value, rule: Value, host: Host, port: u16) -> OutboundKind {
    let value = config(geo, rule);
    let config = dubhe::Config::from_json(&value.to_string()).unwrap();
    let router = Router::new(&config).unwrap();
    router
        .select_outbound("socks", Network::Tcp, &Target { host, port })
        .kind
}

fn domain(name: &str) -> Host {
    Host::Domain(name.to_owned())
}

fn ip(text: &str) -> Host {
    Host::Ip(text.parse().unwrap())
}

/// 真实数据集目录。用 `tools/fetch_geodata.sh` 下载。
fn real_geodata(name: &str) -> Option<std::path::PathBuf> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".test-artifacts/geodata")
        .join(name);
    path.is_file().then_some(path)
}

// ---------------------------------------------------------------------------
// 域名匹配语义
// ---------------------------------------------------------------------------

#[test]
fn geosite_full_matches_exact_only() {
    let dir = tempfile::tempdir().unwrap();
    let site = encode_geosite(&[("exact", &[("exact.test", 3)])]);
    let geosite = write(dir.path(), "geosite.dat", &site);
    // type 3 = Full（整域相等）。
    assert_eq!(
        select(
            json!({"geosite": geosite.clone()}),
            json!({"domains": ["geosite:exact"], "outbound": "reject"}),
            domain("exact.test"),
            443
        ),
        OutboundKind::Reject
    );
    assert_eq!(
        select(
            json!({"geosite": geosite}),
            json!({"domains": ["geosite:exact"], "outbound": "reject"}),
            domain("sub.exact.test"),
            443
        ),
        OutboundKind::Direct
    );
}

#[test]
fn geosite_substr_matches_substring_not_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let site = encode_geosite(&[("sub", &[("ads", 0)])]);
    let geosite = write(dir.path(), "geosite.dat", &site);
    // type 0 = Substr；曾被错映射成后缀，导致 myads.test 不命中。
    assert_eq!(
        select(
            json!({"geosite": geosite.clone()}),
            json!({"domains": ["geosite:sub"], "outbound": "reject"}),
            domain("myads.test"),
            443
        ),
        OutboundKind::Reject
    );
    assert_eq!(
        select(
            json!({"geosite": geosite}),
            json!({"domains": ["geosite:sub"], "outbound": "reject"}),
            domain("clean.test"),
            443
        ),
        OutboundKind::Direct
    );
}

/// 同一 `domains` 数组内的普通值与地理引用必须取并集。
#[test]
fn domains_array_is_union_of_plain_and_geo() {
    let dir = tempfile::tempdir().unwrap();
    let site = encode_geosite(&[("t", &[("blocked.test", 3)])]);
    let geosite = write(dir.path(), "geosite.dat", &site);
    let rule = json!({"domains": ["example.org", "geosite:t"], "outbound": "reject"});
    for host in ["example.org", "blocked.test"] {
        assert_eq!(
            select(
                json!({"geosite": geosite.clone()}),
                rule.clone(),
                domain(host),
                443
            ),
            OutboundKind::Reject,
            "{host} 应在并集里"
        );
    }
}

/// `Full` 与后缀混合时，两者是并集，不是「必须同时成立」。
#[test]
fn geosite_mixed_full_and_suffix_are_or_combined() {
    let dir = tempfile::tempdir().unwrap();
    let site = encode_geosite(&[("mixed", &[("exact.test", 3), ("suffix.test", 2)])]);
    let geosite = write(dir.path(), "geosite.dat", &site);
    for host in ["exact.test", "sub.suffix.test"] {
        assert_eq!(
            select(
                json!({"geosite": geosite.clone()}),
                json!({"domains": ["geosite:mixed"], "outbound": "reject"}),
                domain(host),
                443
            ),
            OutboundKind::Reject,
            "{host} 应命中"
        );
    }
}

/// 空分类必须「永不匹配」，不能被当成「没有条件」。
#[test]
fn empty_geosite_category_never_matches() {
    let dir = tempfile::tempdir().unwrap();
    let site = encode_geosite(&[("empty", &[])]);
    let geosite = write(dir.path(), "geosite.dat", &site);
    let rule = json!({"domains": ["geosite:empty"], "outbound": "reject"});
    for host in [domain("anything.test"), ip("127.0.0.1")] {
        assert_eq!(
            select(json!({"geosite": geosite.clone()}), rule.clone(), host, 443),
            OutboundKind::Direct,
            "空分类不应匹配任何目标"
        );
    }
}

// ---------------------------------------------------------------------------
// IP 匹配语义
// ---------------------------------------------------------------------------

#[test]
fn geoip_cidr_matches_and_is_union_with_plain_cidr() {
    let dir = tempfile::tempdir().unwrap();
    let dat = encode_geoip(&[("loop", &[([127, 0, 0, 0], 8)])]);
    let geoip = write(dir.path(), "geoip.dat", &dat);
    let rule = json!({"ip_cidrs": ["10.0.0.0/8", "geoip:loop"], "outbound": "reject"});
    for host in ["127.0.0.1", "10.1.2.3"] {
        assert_eq!(
            select(json!({"geoip": geoip.clone()}), rule.clone(), ip(host), 443),
            OutboundKind::Reject,
            "{host} 应在 CIDR 并集里"
        );
    }
    assert_eq!(
        select(json!({"geoip": geoip}), rule, ip("192.0.2.1"), 443),
        OutboundKind::Direct
    );
}

/// 空 geoip 分类同样必须「永不匹配」。
#[test]
fn empty_geoip_category_never_matches() {
    let dir = tempfile::tempdir().unwrap();
    let dat = encode_geoip(&[("empty", &[])]);
    let geoip = write(dir.path(), "geoip.dat", &dat);
    assert_eq!(
        select(
            json!({"geoip": geoip}),
            json!({"ip_cidrs": ["geoip:empty"], "outbound": "reject"}),
            ip("127.0.0.1"),
            443
        ),
        OutboundKind::Direct
    );
}

/// CIDR 与 mmdb 必须取并集（都来自 `ip_cidrs` 数组）。
#[test]
fn ip_cidrs_array_is_union_of_cidr_and_mmdb() {
    let Some(mmdb) = real_geodata("Country.mmdb") else {
        eprintln!("跳过：未下载 Country.mmdb");
        return;
    };
    let rule = json!({"ip_cidrs": ["127.0.0.0/8", "mmdb:CN"], "outbound": "reject"});
    let geo = json!({"mmdb": mmdb.display().to_string()});
    // 回环命中 CIDR。
    assert_eq!(
        select(geo.clone(), rule.clone(), ip("127.0.0.1"), 443),
        OutboundKind::Reject
    );
    // 中国地址命中 mmdb。
    assert_eq!(
        select(geo.clone(), rule, ip("223.5.5.5"), 80),
        OutboundKind::Reject
    );
    // 两者都不命中。
    assert_eq!(
        select(
            geo,
            json!({"ip_cidrs": ["127.0.0.0/8", "mmdb:CN"], "outbound": "reject"}),
            ip("8.8.8.8"),
            443
        ),
        OutboundKind::Direct
    );
}

// ---------------------------------------------------------------------------
// rule-set
// ---------------------------------------------------------------------------

#[test]
fn rule_set_source_json_matches_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let rules = json!({
        "version": 3,
        "rules": [{"domain_suffix": ["blocked.test"]}]
    });
    let path = write(dir.path(), "rules.json", rules.to_string().as_bytes());
    assert_eq!(
        select(
            json!({"rule_sets": [{"tag": "ads", "path": path.clone()}]}),
            json!({"domains": ["rule_set:ads"], "outbound": "reject"}),
            domain("sub.blocked.test"),
            443
        ),
        OutboundKind::Reject
    );
    assert_eq!(
        select(
            json!({"rule_sets": [{"tag": "ads", "path": path}]}),
            json!({"domains": ["rule_set:ads"], "outbound": "reject"}),
            domain("ok.test"),
            443
        ),
        OutboundKind::Direct
    );
}

/// rule-set 里的正则保留原文大小写：`\D` 与 `\d` 语义相反。
#[test]
fn rule_set_regex_keeps_original_case() {
    let dir = tempfile::tempdir().unwrap();
    let rules = json!({
        "version": 3,
        "rules": [{"domain_regex": ["^\\D+\\.test$"]}]
    });
    let path = write(dir.path(), "rules.json", rules.to_string().as_bytes());
    // `\D` = 非数字：abc.test 命中，123.test 不命中。
    assert_eq!(
        select(
            json!({"rule_sets": [{"tag": "re", "path": path.clone()}]}),
            json!({"domains": ["rule_set:re"], "outbound": "reject"}),
            domain("abc.test"),
            443
        ),
        OutboundKind::Reject
    );
    assert_eq!(
        select(
            json!({"rule_sets": [{"tag": "re", "path": path}]}),
            json!({"domains": ["rule_set:re"], "outbound": "reject"}),
            domain("123.test"),
            443
        ),
        OutboundKind::Direct
    );
}

/// sing-box 允许单个字符串代替数组；丢它会静默少一条条件。
#[test]
fn rule_set_accepts_scalar_string() {
    let dir = tempfile::tempdir().unwrap();
    let rules = json!({"version": 3, "rules": [{"domain": "a.test"}]});
    let path = write(dir.path(), "rules.json", rules.to_string().as_bytes());
    assert_eq!(
        select(
            json!({"rule_sets": [{"tag": "s", "path": path}]}),
            json!({"domains": ["rule_set:s"], "outbound": "reject"}),
            domain("a.test"),
            443
        ),
        OutboundKind::Reject
    );
}

/// 字段类型错误必须报错，不能被当成「字段不存在」。
#[test]
fn rule_set_rejects_wrong_value_type() {
    let dir = tempfile::tempdir().unwrap();
    let rules = json!({"version": 3, "rules": [{"domain": 42}]});
    let path = write(dir.path(), "rules.json", rules.to_string().as_bytes());
    let error = check_error(&config(
        json!({"rule_sets": [{"tag": "t", "path": path}]}),
        json!({"domains": ["rule_set:t"], "outbound": "reject"}),
    ));
    assert!(error.contains("domain"), "{error}");
}

/// sing-box 的 `domain_suffix: [".a.test"]` 只匹配子域，不含根域。
/// （实测 sing-box 1.14.4 `rule-set match`：a.test 不匹配，sub.a.test 匹配）
#[test]
fn rule_set_leading_dot_suffix_requires_subdomain() {
    let dir = tempfile::tempdir().unwrap();
    let rules = json!({"version": 3, "rules": [{"domain_suffix": [".a.test"]}]});
    let path = write(dir.path(), "rules.json", rules.to_string().as_bytes());
    let geo = json!({"rule_sets": [{"tag": "s", "path": path}]});
    let rule = json!({"domains": ["rule_set:s"], "outbound": "reject"});
    assert_eq!(
        select(geo.clone(), rule.clone(), domain("a.test"), 443),
        OutboundKind::Direct,
        "根域不应匹配前导点后缀"
    );
    assert_eq!(
        select(geo, rule, domain("sub.a.test"), 443),
        OutboundKind::Reject,
        "子域应匹配"
    );
}

/// sing-box 允许裸 IP，等价于 /32 或 /128。
#[test]
fn rule_set_accepts_bare_ip() {
    let dir = tempfile::tempdir().unwrap();
    let rules = json!({"version": 3, "rules": [{"ip_cidr": ["192.0.2.1"]}]});
    let path = write(dir.path(), "rules.json", rules.to_string().as_bytes());
    assert_eq!(
        select(
            json!({"rule_sets": [{"tag": "s", "path": path}]}),
            json!({"ip_cidrs": ["rule_set:s"], "outbound": "reject"}),
            ip("192.0.2.1"),
            443
        ),
        OutboundKind::Reject
    );
}

/// `type: "default"` 与 `invert: false` 是 sing-box 的合法显式写法，
/// 语义上不改变任何东西，应当放行。
#[test]
fn rule_set_accepts_default_type_and_invert_false() {
    let dir = tempfile::tempdir().unwrap();
    let rules = json!({
        "version": 3,
        "rules": [{"type": "default", "invert": false, "domain": ["a.test"]}]
    });
    let path = write(dir.path(), "rules.json", rules.to_string().as_bytes());
    assert_eq!(
        select(
            json!({"rule_sets": [{"tag": "s", "path": path}]}),
            json!({"domains": ["rule_set:s"], "outbound": "reject"}),
            domain("a.test"),
            443
        ),
        OutboundKind::Reject
    );
}

/// 只含 IP 的 rule-set 用在 `domains` 里必须报错：否则阻断规则永不命中。
#[test]
fn rule_set_ip_only_in_domains_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rules = json!({"version": 3, "rules": [{"ip_cidr": ["192.0.2.1"]}]});
    let path = write(dir.path(), "rules.json", rules.to_string().as_bytes());
    let error = check_error(&config(
        json!({"rule_sets": [{"tag": "t", "path": path}]}),
        json!({"domains": ["rule_set:t"], "outbound": "reject"}),
    ));
    assert!(error.contains("不含域名项"), "{error}");
}

// ---------------------------------------------------------------------------
// 失败行为
// ---------------------------------------------------------------------------

fn check_error(value: &Value) -> String {
    let config = dubhe::Config::from_json(&value.to_string()).unwrap();
    dubhe::Server::check(&config).unwrap_err().to_string()
}

/// rule-set 只接受纯域名/IP 子集；含其它条件必须显式拒绝，
/// 不能解析后静默丢掉条件、放大匹配范围。
#[test]
fn rule_set_with_unsupported_condition_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rules = json!({
        "version": 3,
        "rules": [{"domain": ["blocked.test"], "port": [443]}]
    });
    let path = write(dir.path(), "rules.json", rules.to_string().as_bytes());
    let error = check_error(&config(
        json!({"rule_sets": [{"tag": "t", "path": path}]}),
        json!({"domains": ["rule_set:t"], "outbound": "reject"}),
    ));
    assert!(error.contains("port"), "应指出不支持的条件：{error}");
}

#[test]
fn rule_set_with_logical_rule_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rules = json!({
        "version": 3,
        "rules": [{"type": "logical", "mode": "and", "rules": []}]
    });
    let path = write(dir.path(), "rules.json", rules.to_string().as_bytes());
    let error = check_error(&config(
        json!({"rule_sets": [{"tag": "t", "path": path}]}),
        json!({"domains": ["rule_set:t"], "outbound": "reject"}),
    ));
    // 错误信息会点名第一个不支持的字段（这里是 `type` 或 `mode`）。
    assert!(
        error.contains("不支持的条件"),
        "应显式拒绝逻辑规则：{error}"
    );
}

#[test]
fn rule_set_with_invert_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rules = json!({
        "version": 3,
        "rules": [{"domain": ["blocked.test"], "invert": true}]
    });
    let path = write(dir.path(), "rules.json", rules.to_string().as_bytes());
    let error = check_error(&config(
        json!({"rule_sets": [{"tag": "t", "path": path}]}),
        json!({"domains": ["rule_set:t"], "outbound": "reject"}),
    ));
    assert!(error.contains("invert"), "{error}");
}

#[test]
fn rule_set_duplicate_tag_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let rules = json!({"version": 3, "rules": [{"domain": ["a.test"]}]});
    let path = write(dir.path(), "a.json", rules.to_string().as_bytes());
    let error = check_error(&config(
        json!({"rule_sets": [
            {"tag": "dup", "path": path.clone()},
            {"tag": "DUP", "path": path}
        ]}),
        json!({"domains": ["rule_set:dup"], "outbound": "reject"}),
    ));
    assert!(error.contains("重复"), "{error}");
}

/// rule-set 与 geosite 各用独立命名空间，不能互相串。
#[test]
fn rule_set_namespace_is_separate_from_geosite() {
    let dir = tempfile::tempdir().unwrap();
    let site = encode_geosite(&[("shared", &[("from-geosite.test", 3)])]);
    let geosite = write(dir.path(), "geosite.dat", &site);
    let error = check_error(&config(
        json!({"geosite": geosite}),
        json!({"domains": ["rule_set:shared"], "outbound": "reject"}),
    ));
    assert!(error.contains("rule_sets"), "{error}");
}

#[test]
fn geo_reference_without_geo_section_fails_loudly() {
    let mut value = socks_config();
    value["route"] = json!({
        "default": "direct",
        "rules": [{"domains": ["geosite:cn"], "outbound": "reject"}]
    });
    let error = check_error(&value);
    assert!(error.contains("geo"), "应指出缺少 geo 段：{error}");
}

#[test]
fn missing_geosite_code_fails_loudly() {
    let dir = tempfile::tempdir().unwrap();
    let site = encode_geosite(&[("present", &[("a.test", 3)])]);
    let geosite = write(dir.path(), "geosite.dat", &site);
    let error = check_error(&config(
        json!({"geosite": geosite}),
        json!({"domains": ["geosite:absent"], "outbound": "reject"}),
    ));
    assert!(error.contains("geosite:absent"), "{error}");
}

/// 错把 IP 引用写进 `domains`（或反之）必须报错，而不是静默不匹配。
#[test]
fn geo_reference_in_wrong_field_fails_loudly() {
    let dir = tempfile::tempdir().unwrap();
    let dat = encode_geoip(&[("loop", &[([127, 0, 0, 0], 8)])]);
    let geoip = write(dir.path(), "geoip.dat", &dat);
    let error = check_error(&config(
        json!({"geoip": geoip.clone()}),
        json!({"domains": ["geoip:loop"], "outbound": "reject"}),
    ));
    assert!(error.contains("ip_cidrs"), "{error}");
    let error = check_error(&config(
        json!({"geoip": geoip}),
        json!({"ip_cidrs": ["geosite:cn"], "outbound": "reject"}),
    ));
    assert!(error.contains("domains"), "{error}");
}

// ---------------------------------------------------------------------------
// 真实数据集
// ---------------------------------------------------------------------------

/// 真实 `geosite.dat`：`google.com` 是 **Domain（后缀）**，因此子域命中。
#[test]
fn real_geosite_classifies_known_domains() {
    let Some(geosite) = real_geodata("geosite.dat") else {
        eprintln!("跳过：未下载 geosite.dat（tools/fetch_geodata.sh）");
        return;
    };
    let geo = json!({"geosite": geosite.display().to_string()});
    let rule = json!({"domains": ["geosite:google"], "outbound": "reject"});
    for host in ["google.com", "www.google.com", "mail.gmail.com"] {
        assert_eq!(
            select(geo.clone(), rule.clone(), domain(host), 443),
            OutboundKind::Reject,
            "{host} 应命中 geosite:google"
        );
    }
    assert_eq!(
        select(geo, rule, domain("baidu.com"), 443),
        OutboundKind::Direct
    );
}

#[test]
fn real_geoip_classifies_known_addresses() {
    let Some(geoip) = real_geodata("geoip.dat") else {
        eprintln!("跳过：未下载 geoip.dat");
        return;
    };
    let geo = json!({"geoip": geoip.display().to_string()});
    let rule = json!({"ip_cidrs": ["geoip:cn"], "outbound": "reject"});
    assert_eq!(
        select(geo.clone(), rule.clone(), ip("223.5.5.5"), 80),
        OutboundKind::Reject
    );
    assert_eq!(select(geo, rule, ip("8.8.8.8"), 443), OutboundKind::Direct);
}

#[test]
fn real_mmdb_classifies_known_addresses() {
    let Some(mmdb) = real_geodata("Country.mmdb") else {
        eprintln!("跳过：未下载 Country.mmdb");
        return;
    };
    let geo = json!({"mmdb": mmdb.display().to_string()});
    let rule = json!({"ip_cidrs": ["mmdb:CN"], "outbound": "reject"});
    assert_eq!(
        select(geo.clone(), rule.clone(), ip("223.5.5.5"), 80),
        OutboundKind::Reject
    );
    assert_eq!(select(geo, rule, ip("8.8.8.8"), 443), OutboundKind::Direct);
}

/// 端到端接线：规则命中 reject 时数据不会到达目标。
///
/// 目标用**可达**的本机 echo（回环），因此「没有回显」只可能来自拒绝，
/// 不会是拨号失败造成的假象。
#[tokio::test]
async fn geoip_reject_is_wired_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let dat = encode_geoip(&[("loop", &[([127, 0, 0, 0], 8)])]);
    let geoip = write(dir.path(), "geoip.dat", &dat);
    let server = Running::start(config(
        json!({"geoip": geoip}),
        json!({"ip_cidrs": ["geoip:loop"], "outbound": "reject"}),
    ))
    .await;

    let echo = Echo::tcp("127.0.0.1", false).await;
    let mut stream = tokio::net::TcpStream::connect(server.address)
        .await
        .expect("连不上 SOCKS 入口");
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    let mut request = vec![5, 1, 0, 1];
    match echo.address.ip() {
        std::net::IpAddr::V4(v4) => request.extend(v4.octets()),
        std::net::IpAddr::V6(_) => unreachable!(),
    }
    request.extend(echo.address.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    // 必须读完整个 SOCKS 应答（4 字节头 + BND 地址 + 端口），否则剩余
    // 地址字节会被下面的 read 当成「业务回显」。
    let (code, _) = common::read_socks_reply(&mut stream).await;
    // REP 2 = connection not allowed by ruleset。不能只看「有没有回显」：
    // 拨号失败、DNS 失败、超时都会让读操作失败，看起来也像拒绝。
    assert_eq!(code, 2, "命中 reject 应返回 SOCKS REP 2，实际 {code}");

    // 双保险：即便返回 REP 2，也不应有业务数据。
    if code == 0 {
        stream.write_all(b"probe").await.ok();
    }
    let mut buffer = [0u8; 8];
    let read = tokio::time::timeout(Duration::from_millis(800), stream.read(&mut buffer)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_)) | Err(_)),
        "命中 reject 后不应有业务回显"
    );
    server.shutdown().await;
}

/// 反证：同一 geo 配置下，规则不命中时数据能正常转发。
///
/// 这条与上一条成对出现，证明上面的「没有回显」确实来自拒绝，而不是
/// 环境本身不通。
#[tokio::test]
async fn geoip_non_matching_relays_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    // geoip:loop 只含 127.0.0.0/8，但规则只匹配 10.0.0.0/8。
    let dat = encode_geoip(&[("loop", &[([127, 0, 0, 0], 8)])]);
    let geoip = write(dir.path(), "geoip.dat", &dat);
    let server = Running::start(config(
        json!({"geoip": geoip}),
        json!({"ip_cidrs": ["geoip:loop"], "outbound": "reject"}),
    ))
    .await;
    // 让次要规则不命中：再加一条只针对 10/8 的规则在前面，
    // 目标 127.0.0.1 不匹配它，也不匹配 geoip:loop 之外的规则。
    server.shutdown().await;

    // 使用只含 10/8 的 geoip，回环不在其中 → 正常转发。
    let dir2 = tempfile::tempdir().unwrap();
    let dat2 = encode_geoip(&[("ten", &[([10, 0, 0, 0], 8)])]);
    let geoip2 = write(dir2.path(), "geoip.dat", &dat2);
    let server = Running::start(config(
        json!({"geoip": geoip2}),
        json!({"ip_cidrs": ["geoip:ten"], "outbound": "reject"}),
    ))
    .await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    let (mut stream, _) = common::socks(1, common::address(echo.address), server.address).await;
    stream.write_all(b"ok").await.unwrap();
    let mut echoed = [0u8; 2];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ok");
    server.shutdown().await;
}
