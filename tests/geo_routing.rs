//! 地理数据集（`geosite:` / `geoip:` / `mmdb:` / `rule_set:`）端到端行为。
//!
//! 数据集全部由测试**现场生成**：按 Xray 的 proto 定义编码 protobuf、
//! 按 sing-box rule-set source 格式写 JSON。因此这些用例不依赖任何外部
//! 数据文件，也不替第三方数据的正确性背书。

mod common;

use common::{Echo, Running, socks_config};
use serde_json::{Value, json};
use std::{net::SocketAddr, path::Path, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 按 Xray `xray.common.geodata.GeoSiteList` 编码最小 geosite.dat。
///
/// 手写编码而不是复用生产代码的 prost 结构：测试自证会让实现错误被抵消。
/// `(code, [(域名, Xray Domain.Type)])`
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
/// `(code, [(IPv4 字节, 前缀长度)])`
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
    value["outbounds"] = json!([
        {"type": "direct", "tag": "direct"},
        {"type": "reject", "tag": "reject"}
    ]);
    value["route"] = json!({"default": "direct", "rules": [rule]});
    value
}

/// 发一个 SOCKS 请求，断言它**没有**被正常转发。
///
/// 三种预期形态都算「被拒绝」：SOCKS 回复非 0、直接断开、连上但收不到回显。
/// 不能复用 `common::socks`——它内部断言握手成功。
async fn assert_rejected(server: &Running, target: &str, port: u16) {
    let mut stream = tokio::net::TcpStream::connect(server.address)
        .await
        .expect("连不上 SOCKS 入口");
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0], "SOCKS 入口不可用");

    let mut request = vec![5, 1, 0];
    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        request.push(if ip.is_ipv4() { 1 } else { 4 });
        match ip {
            std::net::IpAddr::V4(v4) => request.extend(v4.octets()),
            std::net::IpAddr::V6(v6) => request.extend(v6.octets()),
        }
    } else {
        request.push(3);
        request.push(target.len() as u8);
        request.extend(target.as_bytes());
    }
    request.extend(port.to_be_bytes());
    stream.write_all(&request).await.unwrap();

    let mut head = [0u8; 3];
    if stream.read_exact(&mut head).await.is_err() {
        return;
    }
    assert_eq!(head[0], 5, "无效 SOCKS 回复");
    if head[1] != 0 {
        return;
    }
    let mut buffer = [0u8; 8];
    let read = tokio::time::timeout(Duration::from_millis(800), stream.read(&mut buffer)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_)) | Err(_)),
        "reject 规则下不应收到回显"
    );
}

/// 正常转发：断言回显一致。
async fn assert_relayed(server: &Running, target: SocketAddr, payload: &[u8]) {
    let (mut stream, _) = common::socks(1, common::address(target), server.address).await;
    stream.write_all(payload).await.unwrap();
    let mut echoed = vec![0; payload.len()];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed))
        .await
        .expect("未回显")
        .unwrap();
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn geosite_full_domain_matches_and_rejects() {
    let directory = tempfile::tempdir().unwrap();
    // type=3 是 Xray 的 `Full`（整域相等）。
    let site = encode_geosite(&[("blocked", &[("blocked.test", 3)])]);
    let geosite = write(directory.path(), "geosite.dat", &site);

    let server = Running::start(config(
        json!({"geosite": geosite}),
        json!({"domains": ["geosite:blocked"], "outbound": "reject"}),
    ))
    .await;
    let echo = Echo::tcp("127.0.0.1", false).await;

    // 命中：整域相等被拒绝。
    assert_rejected(&server, "blocked.test", echo.address.port()).await;
    // 未命中：其它域名照常直连，证明规则不是无条件拒绝。
    assert_relayed(&server, echo.address, b"ok").await;
    server.shutdown().await;
}

#[tokio::test]
async fn geoip_cidr_matches_and_rejects() {
    let directory = tempfile::tempdir().unwrap();
    // 127.0.0.0/8 覆盖本机回环，能稳定命中。
    let dat = encode_geoip(&[("loop", &[([127, 0, 0, 0], 8)])]);
    let geoip = write(directory.path(), "geoip.dat", &dat);

    let server = Running::start(config(
        json!({"geoip": geoip}),
        json!({"ip_cidrs": ["geoip:loop"], "outbound": "reject"}),
    ))
    .await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    assert_rejected(&server, "127.0.0.1", echo.address.port()).await;
    server.shutdown().await;
}

#[tokio::test]
async fn rule_set_source_json_matches_suffix() {
    let directory = tempfile::tempdir().unwrap();
    let rules = json!({
        "version": 3,
        "rules": [{"domain_suffix": ["blocked.test"]}]
    });
    let path = write(directory.path(), "rules.json", rules.to_string().as_bytes());

    let server = Running::start(config(
        json!({"rule_sets": [{"tag": "ads", "path": path}]}),
        json!({"domains": ["rule_set:ads"], "outbound": "reject"}),
    ))
    .await;
    let echo = Echo::tcp("127.0.0.1", false).await;
    // 后缀命中：子域也被拒绝。
    assert_rejected(&server, "sub.blocked.test", echo.address.port()).await;
    server.shutdown().await;
}

#[tokio::test]
async fn geo_reference_without_geo_section_fails_loudly() {
    let mut value = socks_config();
    value["outbounds"] = json!([
        {"type": "direct", "tag": "direct"},
        {"type": "reject", "tag": "reject"}
    ]);
    value["route"] = json!({
        "default": "direct",
        "rules": [{"domains": ["geosite:cn"], "outbound": "reject"}]
    });
    let config = dubhe::Config::from_json(&value.to_string()).unwrap();
    let error = dubhe::Server::check(&config).unwrap_err().to_string();
    assert!(error.contains("geo"), "错误信息应指出缺少 geo 段：{error}");
}

#[tokio::test]
async fn missing_geosite_code_fails_loudly() {
    let directory = tempfile::tempdir().unwrap();
    let site = encode_geosite(&[("present", &[("a.test", 3)])]);
    let geosite = write(directory.path(), "geosite.dat", &site);

    let value = config(
        json!({"geosite": geosite}),
        json!({"domains": ["geosite:absent"], "outbound": "reject"}),
    );
    let config = dubhe::Config::from_json(&value.to_string()).unwrap();
    let error = dubhe::Server::check(&config).unwrap_err().to_string();
    assert!(error.contains("geosite:absent"), "{error}");
}
