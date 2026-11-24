//! TCP 首包嗅探：只提取路由需要的 TLS SNI 与 HTTP/1.1 `Host`。
//!
//! dokodemo-door 通过 `peek` 观察首包；其他入站则读取并回放首包（见
//! [`Prefixed`]），业务字节保持不变。嗅探不做完整性校验；客户端可以伪造
//! SNI/Host 影响路由，因此只能作为路由提示，不能当作身份认证。

use std::{
    io,
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use aes::cipher::{Block, BlockCipherEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, Payload},
};
use cryptoxide::{hmac::Hmac, mac::Mac, sha2::Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    time::{Instant, timeout_at},
};

use crate::{
    config::SniffKind,
    forward::Context,
    session::{Host, Target},
};

/// 单次嗅探最多观察的字节数；超过仍无法判定则放弃。
pub(crate) const MAX_SNIFF: usize = 8192;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Sniffed {
    /// 当前缓冲区不足以判定，调用方应继续等待数据。
    NeedMore,
    /// 不是可识别的 TLS ClientHello / HTTP/1.1 请求，或没有可用域名。
    Invalid,
    Domain(String),
}

fn valid_domain(value: &str) -> bool {
    (1..=253).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_graphic())
        && value.parse::<std::net::IpAddr>().is_err()
}

/// 解析 TLS 记录层中的 ClientHello SNI。
///
/// 只接受单个完整握手记录；跨记录分片的 ClientHello 视为不可嗅探。
pub(crate) fn tls_server_name(input: &[u8]) -> Sniffed {
    if input.len() < 5 {
        return Sniffed::NeedMore;
    }
    if input[0] != 0x16 || input[1] != 0x03 {
        return Sniffed::Invalid;
    }
    let record_len = u16::from_be_bytes([input[3], input[4]]) as usize;
    if record_len == 0 {
        return Sniffed::Invalid;
    }
    if input.len() < 5 + record_len {
        return Sniffed::NeedMore;
    }
    let record = &input[5..5 + record_len];
    if record.first() != Some(&0x01) {
        return Sniffed::Invalid;
    }
    let Some(header) = record.get(1..4) else {
        return Sniffed::Invalid;
    };
    let hello_len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    let Some(hello) = record.get(4..4 + hello_len) else {
        return Sniffed::Invalid;
    };
    client_hello(hello)
}

fn client_hello(body: &[u8]) -> Sniffed {
    // version(2) + random(32) + session_id_len(1)：正好 34 字节时下一个
    // 字段还不存在，必须先要求 >34，不能先检查 <34 再索引。
    if body.len() <= 34 {
        return Sniffed::Invalid;
    }
    let mut offset = 34;
    let session_len = body[offset] as usize;
    offset += 1;
    if body.len() < offset + session_len {
        return Sniffed::Invalid;
    }
    offset += session_len;
    let Some(length_bytes) = body.get(offset..offset + 2) else {
        return Sniffed::Invalid;
    };
    let suites = u16::from_be_bytes([length_bytes[0], length_bytes[1]]) as usize;
    offset += 2;
    if body.len() < offset + suites + 1 {
        return Sniffed::Invalid;
    }
    offset += suites;
    let compression = body[offset] as usize;
    offset += 1;
    if body.len() < offset + compression + 2 {
        return Sniffed::Invalid;
    }
    offset += compression;
    let extensions = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2;
    if body.len() < offset + extensions {
        return Sniffed::Invalid;
    }
    let end = offset + extensions;
    while offset + 4 <= end {
        let kind = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let length = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        offset += 4;
        let Some(data) = body.get(offset..offset + length) else {
            return Sniffed::Invalid;
        };
        if kind == 0x0000 {
            return server_name(data);
        }
        offset += length;
    }
    Sniffed::Invalid
}

fn server_name(data: &[u8]) -> Sniffed {
    let Some(list) = data.get(..2) else {
        return Sniffed::Invalid;
    };
    let length = u16::from_be_bytes([list[0], list[1]]) as usize;
    if data.len() < 2 + length {
        return Sniffed::Invalid;
    }
    let mut offset = 2;
    let end = 2 + length;
    while offset + 3 <= end {
        let kind = data[offset];
        let name_len = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;
        offset += 3;
        let Some(name) = data.get(offset..offset + name_len) else {
            return Sniffed::Invalid;
        };
        if kind == 0
            && let Ok(name) = std::str::from_utf8(name)
            && valid_domain(name)
        {
            return Sniffed::Domain(name.to_owned());
        }
        offset += name_len;
    }
    Sniffed::Invalid
}

/// 解析 HTTP/1.1 请求头中的 `Host`。
pub(crate) fn http_host(input: &[u8]) -> Sniffed {
    let Some(end) = input.windows(4).position(|window| window == b"\r\n\r\n") else {
        return if input.len() >= MAX_SNIFF {
            Sniffed::Invalid
        } else {
            Sniffed::NeedMore
        };
    };
    let Ok(head) = std::str::from_utf8(&input[..end]) else {
        return Sniffed::Invalid;
    };
    let mut lines = head.split("\r\n");
    let Some(request) = lines.next() else {
        return Sniffed::Invalid;
    };
    if request.split(' ').count() != 3 {
        return Sniffed::Invalid;
    }
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("host") {
            continue;
        }
        let host = value.trim();
        let host = if let Some((name, port)) = host.rsplit_once(':') {
            // IPv6 字面量或其它多冒号形式不产生可用域名；端口必须是十进制。
            if host.matches(':').count() != 1
                || port.is_empty()
                || !port.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Sniffed::Invalid;
            }
            name
        } else {
            host
        };
        return if valid_domain(host) {
            Sniffed::Domain(host.to_owned())
        } else {
            Sniffed::Invalid
        };
    }
    Sniffed::Invalid
}

/// 按首字节分派到 TLS ClientHello 或 HTTP/1.1 请求解析。
pub(crate) fn detect(input: &[u8]) -> Sniffed {
    if input.first() == Some(&0x16) {
        tls_server_name(input)
    } else {
        http_host(input)
    }
}

/// 读取并回放首包：先读取直到解析出域名、判定失败、达到上限或期限。
///
/// 返回已消费的字节，调用方必须用 [`Prefixed`] 回放，业务流不受影响。
pub(crate) async fn read_payload<S: AsyncRead + Unpin>(
    io: &mut S,
    limit: Duration,
) -> (Option<(SniffKind, String)>, Vec<u8>) {
    let deadline = Instant::now() + limit;
    let mut buffer = Vec::with_capacity(1024);
    loop {
        match detect(&buffer) {
            Sniffed::Domain(domain) => {
                let kind = if buffer.first() == Some(&0x16) {
                    SniffKind::Tls
                } else {
                    SniffKind::Http
                };
                return (Some((kind, domain)), buffer);
            }
            Sniffed::Invalid => return (None, buffer),
            Sniffed::NeedMore => {}
        }
        if buffer.len() >= MAX_SNIFF {
            return (None, buffer);
        }
        let mut chunk = [0u8; 1024];
        let length = match timeout_at(deadline, io.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return (None, buffer),
            Ok(Ok(length)) => length,
        };
        buffer.extend_from_slice(&chunk[..length]);
    }
}

/// 嗅探并按策略生成路由目标与拨号目标。
///
/// 未启用、入口不在策略内或无法识别时，两个目标都保持原值；识别成功时
/// 路由目标改用域名，拨号目标仅在 `dest_override` 允许且未设置
/// `route_only` 时改用域名。
pub(crate) async fn sniff_route<S>(
    ctx: &Context,
    inbound: &str,
    stream: S,
    target: &Target,
) -> (Prefixed<S>, Target, Target)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    sniff_route_read(ctx, inbound, stream, target).await
}

/// 与 [`sniff_route`] 相同，但**只要求读能力**。
///
/// 供「读写已分离」的协议使用（Hysteria2/TUIC 的 QUIC 流：读和写是两个
/// 独立的 handle，写侧还需要在失败分支调用 `finish()`，不能与读侧合并成
/// 一个对象）。调用方拿到 `Prefixed` 的读侧后自行与写侧 `join`。
pub(crate) async fn sniff_route_read<S>(
    ctx: &Context,
    inbound: &str,
    stream: S,
    target: &Target,
) -> (Prefixed<S>, Target, Target)
where
    S: AsyncRead + Unpin,
{
    let mut stream = stream;
    let (prefix, route, dial) = sniff_route_parts(ctx, inbound, &mut stream, target).await;
    (Prefixed::new(prefix, stream), route, dial)
}

/// 只做嗅探并返回已消费的前缀，由调用方决定怎么回放。
///
/// 供需要保留底层句柄能力（例如 quinn 的 `RecvStream::stop()`）的协议使用。
pub(crate) async fn sniff_route_parts<S>(
    ctx: &Context,
    inbound: &str,
    stream: &mut S,
    target: &Target,
) -> (Vec<u8>, Target, Target)
where
    S: AsyncRead + Unpin,
{
    let Some(policy) = ctx.sniff_policy(inbound) else {
        return (Vec::new(), target.clone(), target.clone());
    };
    let (sniffed, prefix) = read_payload(stream, policy.timeout()).await;
    let Some((kind, domain)) = sniffed else {
        return (prefix, target.clone(), target.clone());
    };
    let route = Target {
        host: Host::Domain(domain),
        port: target.port,
    };
    let dial = if policy.overrides(kind) {
        route.clone()
    } else {
        target.clone()
    };
    (prefix, route, dial)
}

/// UDP 首包的 QUIC Initial SNI 只用于选路。
///
/// UDP 没有可回放的流，也没有稳定的会话目标；因此即使配置了
/// `dest_override`，这里也只返回用于路由的目标，实际发送目标保持不变。
pub(crate) fn udp_route_target(
    ctx: &Context,
    inbound: &str,
    target: &Target,
    payload: &[u8],
) -> Target {
    if ctx.sniff_policy(inbound).is_none() {
        return target.clone();
    }
    let Some(domain) = quic_server_name(payload) else {
        return target.clone();
    };
    Target {
        host: Host::Domain(domain),
        port: target.port,
    }
}

/// RFC 9001 的 QUIC v1/v2 初始盐。
const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// 单个数据报内最多检查的合并 QUIC 包数量。
const QUIC_MAX_COALESCED: usize = 8;

/// 解析数据报中的 QUIC Initial 包并取出 ClientHello 的 SNI。
///
/// 支持 RFC 9000 的合并包（coalesced packets）：按长首部 Length 字段逐个
/// 跳过 0-RTT/Handshake 等包，直到找到可解密的 v1/v2 Initial。不处理重传、
/// 0-RTT 早期数据或短首部包；任何长度、AEAD 校验或帧解析失败都返回 `None`。
pub(crate) fn quic_server_name(datagram: &[u8]) -> Option<String> {
    let mut rest = datagram;
    for _ in 0..QUIC_MAX_COALESCED {
        if rest.is_empty() {
            return None;
        }
        if let Some(name) = initial_server_name(rest) {
            return Some(name);
        }
        rest = rest.get(long_header_packet_len(rest)?..)?;
    }
    None
}

/// 计算一个长首部 QUIC 包的总长度，用于跳到合并数据报中的下一个包。
///
/// Initial 含 Token 长度字段；0-RTT/Handshake 不含。Version Negotiation 与
/// Retry 没有通用 Length 字段，遇到即停止。
fn long_header_packet_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < 7 || packet[0] & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(packet[1..5].try_into().ok()?);
    if version == 0 {
        return None;
    }
    let kind = (packet[0] >> 4) & 0x03;
    if kind == 3 {
        return None;
    }
    let mut offset = 5;
    let dcid_len = *packet.get(offset)? as usize;
    offset += 1;
    if dcid_len > 20 {
        return None;
    }
    offset = offset.checked_add(dcid_len)?;
    let scid_len = *packet.get(offset)? as usize;
    offset += 1;
    if scid_len > 20 {
        return None;
    }
    offset = offset.checked_add(scid_len)?;
    if kind == 0 {
        let token_len = usize::try_from(varint(packet, &mut offset)?).ok()?;
        offset = offset.checked_add(token_len)?;
    }
    let length = usize::try_from(varint(packet, &mut offset)?).ok()?;
    let end = offset.checked_add(length)?;
    (end <= packet.len()).then_some(end)
}

/// 尝试把一个 v1/v2 Initial 包解密并提取 SNI；失败返回 `None`。
fn initial_server_name(packet: &[u8]) -> Option<String> {
    if packet.len() < 7 || packet[0] & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(packet[1..5].try_into().ok()?);
    // 长首部 0x30 位：v1 Initial = 0，v2 Initial = 1。
    let (salt, initial_bits) = match version {
        1 => (&QUIC_V1_SALT, 0x00),
        0x6b33_43cf => (&QUIC_V2_SALT, 0x10),
        _ => return None,
    };
    if packet[0] & 0x30 != initial_bits {
        return None;
    }
    let mut offset = 5;
    let dcid_len = *packet.get(offset)? as usize;
    offset += 1;
    if dcid_len == 0 || dcid_len > 20 {
        return None;
    }
    let dcid = packet.get(offset..offset + dcid_len)?;
    offset += dcid_len;
    let scid_len = *packet.get(offset)? as usize;
    offset += 1;
    if scid_len > 20 {
        return None;
    }
    offset += scid_len;
    let token_len = usize::try_from(varint(packet, &mut offset)?).ok()?;
    offset = offset.checked_add(token_len)?;
    if offset > packet.len() {
        return None;
    }
    let length = usize::try_from(varint(packet, &mut offset)?).ok()?;
    let pn_offset = offset;
    let sample = packet.get(pn_offset + 4..pn_offset + 20)?;

    let initial_secret = hkdf_extract(salt, dcid);
    let client_secret = hkdf_expand_label(&initial_secret, b"client in", 32);
    let key = hkdf_expand_label(&client_secret, b"quic key", 16);
    let iv = hkdf_expand_label(&client_secret, b"quic iv", 12);
    let hp = hkdf_expand_label(&client_secret, b"quic hp", 16);

    let mut mask: [u8; 16] = sample.try_into().ok()?;
    let block = aes::Aes128::new_from_slice(&hp).ok()?;
    let mask_block: &mut Block<aes::Aes128> = (&mut mask[..]).try_into().ok()?;
    block.encrypt_block(mask_block);
    let first = packet[0] ^ (mask[0] & 0x0f);
    let pn_len = ((first & 0x03) + 1) as usize;
    let mut pn = 0u64;
    for (index, byte) in packet
        .get(pn_offset..pn_offset + pn_len)?
        .iter()
        .enumerate()
    {
        pn = (pn << 8) | (byte ^ mask[1 + index]) as u64;
    }
    let ciphertext_len = length.checked_sub(pn_len)?;
    let ciphertext = packet.get(pn_offset + pn_len..pn_offset + pn_len + ciphertext_len)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv);
    for (index, byte) in pn.to_be_bytes().iter().enumerate() {
        nonce[4 + index] ^= byte;
    }
    // AAD 必须使用已移除首部保护的首字节与 packet number，而不是线上字节。
    let mut aad = packet.get(..pn_offset)?.to_vec();
    aad[0] = first;
    for (index, byte) in packet
        .get(pn_offset..pn_offset + pn_len)?
        .iter()
        .enumerate()
    {
        aad.push(byte ^ mask[1 + index]);
    }
    let nonce = aes_gcm::Nonce::try_from(nonce.as_slice()).ok()?;
    let plaintext = Aes128Gcm::new_from_slice(&key)
        .ok()?
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .ok()?;
    crypto_frame_sni(&plaintext)
}

/// QUIC varint（RFC 9000 §16），越界返回 `None`。
fn varint(input: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *input.get(*offset)?;
    let length = 1usize << (first >> 6);
    let bytes = input.get(*offset..*offset + length)?;
    *offset += length;
    let mut value = (first & 0x3f) as u64;
    for byte in &bytes[1..] {
        value = (value << 8) | *byte as u64;
    }
    Some(value)
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::new(Sha256::new(), key);
    for part in parts {
        mac.input(part);
    }
    let mut output = [0u8; 32];
    mac.raw_result(&mut output);
    output
}

fn hkdf_extract(salt: &[u8], input: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, &[input])
}

fn hkdf_expand_label(secret: &[u8], label: &[u8], length: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(20 + label.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push((b"tls13 ".len() + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    hkdf_expand(secret, &info, length)
}

fn hkdf_expand(secret: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(length);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while output.len() < length {
        let mut block = previous;
        block.extend_from_slice(info);
        block.push(counter);
        previous = hmac_sha256(secret, &[&block]).to_vec();
        output.extend_from_slice(&previous);
        counter = counter.wrapping_add(1);
        if counter == 0 {
            break;
        }
    }
    output.truncate(length);
    output
}

/// 从 Initial 载荷中取第一个 CRYPTO 帧并解析 TLS ClientHello。
fn crypto_frame_sni(payload: &[u8]) -> Option<String> {
    let mut offset = 0;
    if varint(payload, &mut offset)? != 0 {
        return None;
    }
    let _frame_offset = varint(payload, &mut offset)?;
    let length = usize::try_from(varint(payload, &mut offset)?).ok()?;
    let handshake = payload.get(offset..offset + length)?;
    if handshake.first() != Some(&0x01) {
        return None;
    }
    let hello_len = u32::from_be_bytes([
        0,
        *handshake.get(1)?,
        *handshake.get(2)?,
        *handshake.get(3)?,
    ]) as usize;
    let hello = handshake.get(4..4 + hello_len)?;
    match client_hello(hello) {
        Sniffed::Domain(domain) => Some(domain),
        _ => None,
    }
}

/// 先返回已消费首包、再读取内层流的包装器。
pub(crate) struct Prefixed<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let length = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..length]);
            self.offset += length;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 截断在 ClientHello 字段边界上必须返回 Invalid，不能 panic。
    #[test]
    fn truncated_client_hello_fields_are_not_panics() {
        // record = handshake_type(1) + length(3) + body(34: version+random)
        let mut body = vec![0u8; 34];
        body[0] = 0x03;
        body[1] = 0x03;
        let mut record = vec![0x01, 0x00, 0x00, body.len() as u8];
        record.extend_from_slice(&body);
        let mut input = vec![0x16, 0x03, 0x01, 0x00, record.len() as u8];
        input.extend_from_slice(&record);
        assert_eq!(tls_server_name(&input), Sniffed::Invalid);

        // 更短的 body 也不能 panic。
        for cut in 0..body.len() {
            let mut record = vec![0x01, 0x00, 0x00, cut as u8];
            record.extend_from_slice(&body[..cut]);
            let mut input = vec![0x16, 0x03, 0x01, 0x00, record.len() as u8];
            input.extend_from_slice(&record);
            let _ = tls_server_name(&input);
        }
    }

    fn client_hello(server_name: &str) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.push(0x00); // host_name
        entry.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        entry.extend_from_slice(server_name.as_bytes());
        let mut data = Vec::new();
        data.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        data.extend_from_slice(&entry);
        let mut extension = Vec::new();
        extension.extend_from_slice(&[0x00, 0x00]); // server_name
        extension.extend_from_slice(&(data.len() as u16).to_be_bytes());
        extension.extend_from_slice(&data);
        let extensions = extension;

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0x11; 32]);
        hello.push(0); // session id
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        hello.extend_from_slice(&[0x01, 0x00]); // compression
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let length = hello.len() as u32;
        handshake.extend_from_slice(&length.to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn tls_client_hello_sni_is_extracted() {
        let record = client_hello("sniffed.example");
        assert_eq!(
            tls_server_name(&record),
            Sniffed::Domain("sniffed.example".into())
        );
        for cut in [1, 5, record.len() - 1] {
            assert_eq!(tls_server_name(&record[..cut]), Sniffed::NeedMore);
        }
        let mut broken = record;
        broken[5] = 0x02;
        assert_eq!(tls_server_name(&broken), Sniffed::Invalid);
    }

    fn config(sniffing: &str) -> crate::config::Config {
        crate::config::Config::from_json(&format!(
            r#"{{"version":1,"inbounds":[{{"type":"socks5","tag":"in","listen":"127.0.0.1:0"}}],"outbounds":[{{"type":"direct","tag":"direct"}}],"route":{{"default":"direct"}},"sniffing":{sniffing}}}"#
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn read_payload_replays_every_consumed_byte() {
        let (mut client, server) = tokio::io::duplex(256);
        let record = client_hello("sniffed.example");
        let mut sent = record.clone();
        sent.extend_from_slice(b"payload");
        let written = sent.clone();
        tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(&mut client, &written)
                .await
                .unwrap();
            // 保持连接打开，验证解析完成即返回而不是等待 EOF。
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let mut server = server;
        let (sniffed, prefix) = read_payload(&mut server, Duration::from_millis(500)).await;
        assert_eq!(sniffed, Some((SniffKind::Tls, "sniffed.example".into())));
        assert!(prefix.starts_with(&record));
        // 已消费字节必须按原顺序完整回放，业务流不受嗅探影响。
        let mut stream = Prefixed::new(prefix.clone(), server);
        let mut rest = vec![0u8; sent.len() - prefix.len()];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut rest)
            .await
            .unwrap();
        let mut replayed = prefix;
        replayed.extend_from_slice(&rest);
        assert_eq!(replayed, sent);
    }

    #[tokio::test]
    async fn sniff_route_separates_routing_from_dial_target() {
        let target = Target {
            host: Host::Ip("127.0.0.1".parse().unwrap()),
            port: 443,
        };
        let record = client_hello("sniffed.example");

        let overriding = Context::new(&config(
            r#"{"enabled":true,"dest_override":["tls"],"timeout_ms":20}"#,
        ))
        .unwrap();
        let (_, route, dial) =
            sniff_route(&overriding, "in", tokio::io::duplex(256).1, &target).await;
        // 没有写入数据时回落到原目标。
        assert_eq!(route, target);
        assert_eq!(dial, target);

        let (mut client, server) = tokio::io::duplex(256);
        let writer = tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(&mut client, &record)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let (_, route, dial) = sniff_route(&overriding, "in", server, &target).await;
        assert_eq!(route.host, Host::Domain("sniffed.example".into()));
        assert_eq!(dial, route);
        writer.abort();

        let route_only = Context::new(&config(
            r#"{"enabled":true,"dest_override":["tls"],"route_only":true,"timeout_ms":20}"#,
        ))
        .unwrap();
        let record = client_hello("sniffed.example");
        let (mut client, server) = tokio::io::duplex(256);
        let writer = tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(&mut client, &record)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let (_, route, dial) = sniff_route(&route_only, "in", server, &target).await;
        assert_eq!(route.host, Host::Domain("sniffed.example".into()));
        assert_eq!(dial, target);
        writer.abort();
    }

    fn put_varint(output: &mut Vec<u8>, value: usize) {
        if value <= 63 {
            output.push(value as u8);
        } else if value <= 16_383 {
            output.push(0x40 | (value >> 8) as u8);
            output.push(value as u8);
        } else {
            unreachable!("测试载荷不超过两字节 varint");
        }
    }

    /// 按 RFC 9001 构造一个 v1 Initial 包，用于验证解密与 SNI 提取。
    fn quic_initial(server_name: &str) -> Vec<u8> {
        use aes_gcm::aead::Aead as _;

        let record = client_hello(server_name);
        let handshake = &record[5..];
        let mut payload = Vec::new();
        payload.push(0x00); // CRYPTO
        payload.push(0x00); // offset 0
        put_varint(&mut payload, handshake.len());
        payload.extend_from_slice(handshake);

        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let initial_secret = hkdf_extract(&QUIC_V1_SALT, &dcid);
        let client_secret = hkdf_expand_label(&initial_secret, b"client in", 32);
        let key = hkdf_expand_label(&client_secret, b"quic key", 16);
        let iv = hkdf_expand_label(&client_secret, b"quic iv", 12);
        let hp = hkdf_expand_label(&client_secret, b"quic hp", 16);

        let mut header = vec![0xc0u8, 0, 0, 0, 1, dcid.len() as u8];
        header.extend_from_slice(&dcid);
        header.push(0); // SCID 长度
        header.push(0); // token 长度
        put_varint(&mut header, 1 + payload.len() + 16);
        let pn_offset = header.len();
        header.push(1); // packet number

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv);
        nonce[11] ^= 1;
        let nonce = aes_gcm::Nonce::try_from(nonce.as_slice()).unwrap();
        let ciphertext = Aes128Gcm::new_from_slice(&key)
            .unwrap()
            .encrypt(
                &nonce,
                Payload {
                    msg: &payload,
                    aad: &header,
                },
            )
            .unwrap();
        let mut packet = header;
        packet.extend_from_slice(&ciphertext);

        let mut mask: [u8; 16] = packet[pn_offset + 4..pn_offset + 20].try_into().unwrap();
        let mask_block: &mut Block<aes::Aes128> = (&mut mask[..]).try_into().unwrap();
        aes::Aes128::new_from_slice(&hp)
            .unwrap()
            .encrypt_block(mask_block);
        packet[0] ^= mask[0] & 0x0f;
        packet[pn_offset] ^= mask[1];
        packet
    }

    #[test]
    fn quic_initial_sni_is_extracted_and_garbage_is_ignored() {
        let packet = quic_initial("sniffed.example");
        assert_eq!(quic_server_name(&packet), Some("sniffed.example".into()));
        for cut in [0, 5, 10, packet.len() - 30] {
            assert_eq!(quic_server_name(&packet[..cut]), None, "截断 {cut}");
        }
        let mut broken = packet.clone();
        *broken.last_mut().unwrap() ^= 0xff;
        assert_eq!(quic_server_name(&broken), None, "AEAD 校验必须失败");
        assert_eq!(quic_server_name(b"plain http request"), None);
    }

    /// 构造一个没有 SNI 的长首部 0-RTT 包（类型 1），用于合并包测试。
    fn quic_zero_rtt(payload: &[u8]) -> Vec<u8> {
        let dcid = [0x11u8; 8];
        let mut packet = vec![0xd0u8, 0, 0, 0, 1, dcid.len() as u8];
        packet.extend_from_slice(&dcid);
        packet.push(0); // SCID 长度
        let mut length = Vec::new();
        put_varint(&mut length, payload.len());
        packet.extend_from_slice(&length);
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn coalesced_datagram_finds_a_later_initial_packet() {
        let initial = quic_initial("coalesced.example");
        let mut datagram = quic_zero_rtt(b"zero");
        datagram.extend_from_slice(&initial);
        assert_eq!(
            quic_server_name(&datagram),
            Some("coalesced.example".into())
        );

        // Initial 在前、后续短首部包在后时仍只读取 Initial。
        let mut leading = quic_initial("leading.example");
        leading.extend_from_slice(&[0x40, 0, 0, 0, 0]);
        assert_eq!(quic_server_name(&leading), Some("leading.example".into()));

        // 首个包长度字段声明超出数据报时停止，不越界读取。
        let mut truncated = quic_zero_rtt(b"zero");
        truncated.truncate(truncated.len() - 1);
        assert_eq!(quic_server_name(&truncated), None);
        // 超过合并包数量上限后放弃。
        let mut many = Vec::new();
        for _ in 0..=QUIC_MAX_COALESCED {
            many.extend_from_slice(&quic_zero_rtt(b"zero"));
        }
        assert_eq!(quic_server_name(&many), None);
    }

    #[tokio::test]
    async fn udp_route_target_uses_quic_sni_only_for_routing() {
        let target = Target {
            host: Host::Ip("127.0.0.1".parse().unwrap()),
            port: 443,
        };
        let packet = quic_initial("quic.example");
        let enabled = Context::new(&config(r#"{"enabled":true}"#)).unwrap();
        let route = udp_route_target(&enabled, "in", &target, &packet);
        assert_eq!(route.host, Host::Domain("quic.example".into()));
        assert_eq!(route.port, 443);

        let disabled = Context::new(&config(r#"{"enabled":false}"#)).unwrap();
        assert_eq!(udp_route_target(&disabled, "in", &target, &packet), target);
        // 非 QUIC 载荷保持原目标。
        assert_eq!(
            udp_route_target(&enabled, "in", &target, b"not quic"),
            target
        );
    }

    #[test]
    fn http_host_is_extracted_and_ip_literals_are_ignored() {
        let request = b"GET / HTTP/1.1\r\nHost: sniffed.example:8080\r\n\r\nbody";
        assert_eq!(
            http_host(request),
            Sniffed::Domain("sniffed.example".into())
        );
        assert_eq!(
            http_host(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
            Sniffed::Invalid
        );
        assert_eq!(http_host(b"GET / HTTP/1.1\r\n\r\n"), Sniffed::Invalid);
        assert_eq!(http_host(b"GET / HTTP/1.1\r\nHost: a"), Sniffed::NeedMore);
        assert_eq!(http_host(&[b'x'; MAX_SNIFF]), Sniffed::Invalid);
    }
}
