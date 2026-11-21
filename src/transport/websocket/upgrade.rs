//! 有限 HTTP/1.1 Upgrade；这里只建立承载，不认证代理用户。
//!
//! 调用方须用同一个绝对 `timeout_at` 包住 TLS、整个 `accept` 和后续协议认证，
//! 并在此之前检查实际 TLS 的 ALPN（只允许未协商或 http/1.1）。本模块不刷新期限。
//! `raw_prefix` 必须放在父层原始帧头护栏下方，绝不能直接交给
//! `from_partially_read`，也不能当作已经解帧的业务明文。

use std::io;
use std::net::Ipv6Addr;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http::header::{HeaderValue, SEC_WEBSOCKET_PROTOCOL};
use http::uri::Authority;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{EarlyData, WebSocket};
use crate::util::hex_digit;

const MAX_HEAD: usize = 16_384;
const MAX_HEADERS: usize = 64;
const MAX_TARGET: usize = 12_288;
const MAX_RAW_PREFIX: usize = 16_384;
const MAX_PRE_READ: usize = 32_768;
const READ_CHUNK: usize = 1_024;
#[cfg(test)]
const MAX_PATH: usize = 1_024;
#[cfg(test)]
const MAX_EARLY_DATA: usize = 8_192;

// 包含未经认证的秘密，刻意不实现 Debug。
pub(super) struct Accepted {
    pub raw_prefix: Vec<u8>,
    pub early_data: Vec<u8>,
}

/// 成功时 101 已完整 write_all + flush；两个前缀的所有权只转移一次。
pub(super) async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    config: &crate::config::WebSocket,
) -> io::Result<Accepted> {
    // 配置本应在监听前验证；这里也防止未经准备的直接调用放大输入限额。
    config
        .validate()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "WebSocket 配置无效"))?;

    let (buffer, head_end) = match read_head(io).await {
        Ok(head) => head,
        Err(ReadFailure::Rejected(rejection)) => return reject(io, rejection).await,
        Err(ReadFailure::Io(error)) => return Err(error),
    };
    let handshake = match check_head(&buffer[..head_end], config) {
        Ok(handshake) => handshake,
        Err(rejection) => return reject(io, rejection).await,
    };

    // 成熟库只收到经过门禁的最小握手信息，不保留/转发 URI、任意头或身份。
    let request = http::Request::builder()
        .method(http::Method::GET)
        .version(http::Version::HTTP_11)
        .uri("/")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", handshake.key)
        .body(())
        .map_err(|_| internal_error())?;
    let mut response =
        tungstenite::handshake::server::create_response(&request).map_err(|_| internal_error())?;
    if let Some(protocol) = handshake.protocol {
        response
            .headers_mut()
            .insert(SEC_WEBSOCKET_PROTOCOL, protocol);
    }
    let mut wire = Vec::new();
    tungstenite::handshake::server::write_response(&mut wire, &response)
        .map_err(|_| internal_error())?;
    // 不能在部分 101 写出后再发送 HTTP 错误，取消也由调用方丢弃整个连接。
    io.write_all(&wire)
        .await
        .map_err(|error| io_error(error, "WebSocket HTTP 响应写入失败"))?;
    io.flush()
        .await
        .map_err(|error| io_error(error, "WebSocket HTTP 响应刷新失败"))?;

    Ok(Accepted {
        raw_prefix: buffer[head_end..].to_vec(),
        early_data: handshake.early_data,
    })
}

fn io_error(error: io::Error, message: &'static str) -> io::Error {
    // 不把底层/库错误的 Display 或 Debug（可能含输入）带到日志调用点。
    io::Error::new(error.kind(), message)
}

fn internal_error() -> io::Error {
    io::Error::other("WebSocket HTTP 响应生成失败")
}

#[derive(Clone, Copy)]
enum Rejection {
    BadRequest,
    NotFound,
    TooLarge,
}

impl Rejection {
    fn response(self) -> &'static [u8] {
        match self {
            Self::BadRequest => {
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            }
            Self::NotFound => {
                b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            }
            Self::TooLarge => {
                b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            }
        }
    }
}

async fn reject<S: AsyncWrite + Unpin, T>(io: &mut S, rejection: Rejection) -> io::Result<T> {
    io.write_all(rejection.response())
        .await
        .map_err(|error| io_error(error, "WebSocket HTTP 拒绝响应写入失败"))?;
    io.flush()
        .await
        .map_err(|error| io_error(error, "WebSocket HTTP 拒绝响应刷新失败"))?;
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "WebSocket HTTP 握手被拒绝",
    ))
}

enum ReadFailure {
    Rejected(Rejection),
    Io(io::Error),
}

impl From<Rejection> for ReadFailure {
    fn from(rejection: Rejection) -> Self {
        Self::Rejected(rejection)
    }
}

// httparse 接受裸 LF 和前导空行；额外门禁只负责严格 CRLF、原始行数/长度及
// obs-fold，不替代成熟 HTTP 字段解析。逐字节输入时也只扫描每个字节一次。
#[derive(Default)]
struct HeadBoundary {
    scanned: usize,
    line_start: usize,
    fields: usize,
    target_len: usize,
    target_done: bool,
}

impl HeadBoundary {
    fn scan(&mut self, buffer: &[u8]) -> Result<Option<usize>, Rejection> {
        while self.scanned < buffer.len() {
            let index = self.scanned;
            if index >= MAX_HEAD {
                return Err(Rejection::TooLarge);
            }
            let byte = buffer[index];
            if index > 0 && buffer[index - 1] == b'\r' && byte != b'\n' {
                return Err(Rejection::BadRequest);
            }
            if byte == b'\n' && (index == 0 || buffer[index - 1] != b'\r') {
                return Err(Rejection::BadRequest);
            }
            if self.line_start == 0 {
                if index < 4 {
                    if byte != b"GET "[index] {
                        return Err(Rejection::BadRequest);
                    }
                } else if !self.target_done {
                    if byte == b' ' && self.target_len > 0 {
                        self.target_done = true;
                    } else {
                        if !(0x21..=0x7e).contains(&byte) {
                            return Err(Rejection::BadRequest);
                        }
                        self.target_len =
                            self.target_len.checked_add(1).ok_or(Rejection::TooLarge)?;
                        if self.target_len > MAX_TARGET {
                            return Err(Rejection::TooLarge);
                        }
                    }
                }
            } else if index == self.line_start {
                if byte == b' ' || byte == b'\t' {
                    return Err(Rejection::BadRequest);
                }
                if byte != b'\r' && byte != b'\n' {
                    self.fields = self.fields.checked_add(1).ok_or(Rejection::TooLarge)?;
                    if self.fields > MAX_HEADERS {
                        return Err(Rejection::TooLarge);
                    }
                }
            }
            self.scanned = index.checked_add(1).ok_or(Rejection::TooLarge)?;
            if byte == b'\n' {
                if self.line_start == 0 && !buffer[..index - 1].ends_with(b" HTTP/1.1") {
                    return Err(Rejection::BadRequest);
                }
                if index - 1 == self.line_start {
                    return Ok(Some(self.scanned));
                }
                self.line_start = self.scanned;
            }
        }
        // 刚好到界而没有 CRLFCRLF 就立即失败，不再读取一个字节/HTTP body。
        if buffer.len() >= MAX_HEAD {
            return Err(Rejection::TooLarge);
        }
        Ok(None)
    }
}

async fn read_head<S: AsyncRead + Unpin>(io: &mut S) -> Result<(Vec<u8>, usize), ReadFailure> {
    let mut buffer = Vec::with_capacity(MAX_HEAD);
    let mut boundary = HeadBoundary::default();
    loop {
        let mut chunk = [0; READ_CHUNK];
        let remaining = MAX_HEAD
            .checked_sub(buffer.len())
            .filter(|remaining| *remaining > 0)
            .ok_or(Rejection::TooLarge)?;
        let capacity = remaining.min(READ_CHUNK);
        let read = io
            .read(&mut chunk[..capacity])
            .await
            .map_err(|error| ReadFailure::Io(io_error(error, "WebSocket HTTP 请求读取失败")))?;
        if read == 0 {
            return Err(Rejection::BadRequest.into());
        }
        let total = buffer.len().checked_add(read).ok_or(Rejection::TooLarge)?;
        if total > MAX_PRE_READ {
            return Err(Rejection::TooLarge.into());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(head_end) = boundary.scan(&buffer)? {
            let tail = total.checked_sub(head_end).ok_or(Rejection::TooLarge)?;
            if tail > MAX_RAW_PREFIX {
                return Err(Rejection::TooLarge.into());
            }
            return Ok((buffer, head_end));
        }
    }
}

struct Handshake<'a> {
    key: &'a [u8],
    early_data: Vec<u8>,
    protocol: Option<HeaderValue>,
}

fn singleton<'a>(slot: &mut Option<&'a [u8]>, value: &'a [u8]) -> Result<(), Rejection> {
    if slot.replace(value).is_some() {
        return Err(Rejection::BadRequest);
    }
    Ok(())
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn check_head<'a>(head: &'a [u8], config: &WebSocket) -> Result<Handshake<'a>, Rejection> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(head) {
        Ok(httparse::Status::Complete(end)) if end == head.len() => {}
        Err(httparse::Error::TooManyHeaders) => return Err(Rejection::TooLarge),
        _ => return Err(Rejection::BadRequest),
    }
    if request.method != Some("GET") || request.version != Some(1) {
        return Err(Rejection::BadRequest);
    }
    let target = request.path.ok_or(Rejection::BadRequest)?;
    if target.len() > MAX_TARGET {
        return Err(Rejection::TooLarge);
    }
    let mut host = None;
    let mut key = None;
    let mut version = None;
    let mut upgrade = None;
    let mut protocol = None;
    let mut carrier = None;
    let mut connection_upgrade = false;
    let custom_header = match &config.early_data {
        Some(EarlyData::Header { header_name, .. }) => Some(header_name.as_str()),
        _ => None,
    };
    // 在放入 http::HeaderMap 前检查原始字段多值，不能用 get() 把重复静默折叠。
    for header in request.headers.iter() {
        let name = header.name;
        let value = trim_ows(header.value);
        if name.eq_ignore_ascii_case("host") {
            singleton(&mut host, value)?;
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            singleton(&mut key, value)?;
        } else if name.eq_ignore_ascii_case("sec-websocket-version") {
            singleton(&mut version, value)?;
        } else if name.eq_ignore_ascii_case("upgrade") {
            singleton(&mut upgrade, value)?;
        } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            singleton(&mut protocol, value)?;
        } else if name.eq_ignore_ascii_case("connection") {
            for token in value.split(|byte| *byte == b',') {
                let token = trim_ows(token);
                if token.is_empty() || !token.iter().copied().all(is_token_byte) {
                    return Err(Rejection::BadRequest);
                }
                connection_upgrade |= token.eq_ignore_ascii_case(b"upgrade");
            }
        } else if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            return Err(Rejection::BadRequest);
        }
        if custom_header.is_some_and(|carrier_name| name.eq_ignore_ascii_case(carrier_name)) {
            singleton(&mut carrier, value)?;
        }
    }
    if !connection_upgrade
        || !upgrade.is_some_and(|value| value.eq_ignore_ascii_case(b"websocket"))
        || version != Some(b"13".as_slice())
    {
        return Err(Rejection::BadRequest);
    }
    let key = key.ok_or(Rejection::BadRequest)?;
    if key.len() != 24 {
        return Err(Rejection::BadRequest);
    }
    let decoded_key = STANDARD.decode(key).map_err(|_| Rejection::BadRequest)?;
    if decoded_key.len() != 16 || STANDARD.encode(&decoded_key).as_bytes() != key {
        return Err(Rejection::BadRequest);
    }
    let host = std::str::from_utf8(host.ok_or(Rejection::BadRequest)?)
        .map_err(|_| Rejection::BadRequest)?;
    let host = checked_authority(host)?;
    if let Some(expected) = &config.host {
        let expected = checked_authority(expected)?;
        if !host.matches(&expected) {
            return Err(Rejection::NotFound);
        }
    }
    let (path, query) = checked_target(target)?;
    let early_data = match &config.early_data {
        Some(EarlyData::Path { max_bytes }) => {
            if query.is_some() {
                return Err(Rejection::BadRequest);
            }
            let suffix = path
                .strip_prefix(config.path.as_str())
                .ok_or(Rejection::NotFound)?;
            decode_early(suffix.as_bytes(), *max_bytes)?
        }
        _ => {
            if decode_path(path)? != decode_path(&config.path)? {
                return Err(Rejection::NotFound);
            }
            match &config.early_data {
                Some(EarlyData::Header { max_bytes, .. }) => {
                    decode_early(carrier.unwrap_or_default(), *max_bytes)?
                }
                _ => Vec::new(),
            }
        }
    };
    let protocol_carrier =
        custom_header.is_some_and(|name| name.eq_ignore_ascii_case("sec-websocket-protocol"));
    if !protocol_carrier && protocol.is_some_and(|value| !value.is_empty()) {
        return Err(Rejection::BadRequest);
    }
    let protocol = if protocol_carrier && !early_data.is_empty() {
        // 规范 RawURL 是合法的单个 HTTP token，绝不回显其他载体或失败输入。
        Some(
            HeaderValue::from_bytes(carrier.unwrap_or_default())
                .map_err(|_| Rejection::BadRequest)?,
        )
    } else {
        None
    };
    Ok(Handshake {
        key,
        early_data,
        protocol,
    })
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"/-._~!$&'()*+,;=:@".contains(&byte)
}

fn checked_target(target: &str) -> Result<(&str, Option<&str>), Rejection> {
    // 先用成熟 URI 解析器验证 origin-form，再检查本承载更严格的 ASCII/percent 策略。
    let uri = http::Uri::from_str(target).map_err(|_| Rejection::BadRequest)?;
    if !target.starts_with('/') || uri.scheme().is_some() || uri.authority().is_some() {
        return Err(Rejection::BadRequest);
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    decode_path(path)?;
    if let Some(query) = query {
        let mut bytes = query.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                if bytes.next().and_then(hex_digit).is_none()
                    || bytes.next().and_then(hex_digit).is_none()
                {
                    return Err(Rejection::BadRequest);
                }
            } else if !is_path_byte(byte) && byte != b'?' {
                return Err(Rejection::BadRequest);
            }
        }
    }
    Ok((path, query))
}

fn decode_path(path: &str) -> Result<Vec<u8>, Rejection> {
    if !path.starts_with('/') {
        return Err(Rejection::BadRequest);
    }
    let mut decoded = Vec::with_capacity(path.len());
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = bytes
                .next()
                .and_then(hex_digit)
                .ok_or(Rejection::BadRequest)?;
            let low = bytes
                .next()
                .and_then(hex_digit)
                .ok_or(Rejection::BadRequest)?;
            let byte = (high << 4) | low;
            // 只解码一次；%25 得到的 % 不再作为新的转义或 query/fragment 分隔符。
            if !is_path_byte(byte) && byte != b'%' {
                return Err(Rejection::BadRequest);
            }
            decoded.push(byte);
        } else if is_path_byte(byte) {
            decoded.push(byte);
        } else {
            return Err(Rejection::BadRequest);
        }
    }
    Ok(decoded)
}

struct CheckedAuthority {
    host: String,
    ipv6: Option<Ipv6Addr>,
    port: Option<u16>,
}

impl CheckedAuthority {
    fn matches(&self, expected: &Self) -> bool {
        let same_host = match (self.ipv6, expected.ipv6) {
            (Some(actual), Some(expected)) => actual == expected,
            (None, None) => self.host.eq_ignore_ascii_case(&expected.host),
            _ => false,
        };
        same_host && expected.port.is_none_or(|port| self.port == Some(port))
    }
}

fn checked_authority(value: &str) -> Result<CheckedAuthority, Rejection> {
    if !value.is_ascii() || value.contains(['@', ',']) {
        return Err(Rejection::BadRequest);
    }
    let authority = Authority::from_str(value).map_err(|_| Rejection::BadRequest)?;
    let host = authority.host();
    if host.is_empty() {
        return Err(Rejection::BadRequest);
    }
    // http::Authority 只验证 URI 结构，允许 userinfo/非数字端口/非 IP 方括号；
    // 上面排除 userinfo，下面补足 HTTP Host 的端口与 IPv6 语义，不做 DNS。
    let ipv6 = if host.starts_with('[') {
        let ip = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .ok_or(Rejection::BadRequest)?;
        Some(Ipv6Addr::from_str(ip).map_err(|_| Rejection::BadRequest)?)
    } else {
        // RFC reg-name 的 ASCII 字符，保留尾点，不自行规范化 DNS 名或解析目标。
        if !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&byte))
        {
            return Err(Rejection::BadRequest);
        }
        None
    };
    let suffix = value.strip_prefix(host).ok_or(Rejection::BadRequest)?;
    let port = if suffix.is_empty() {
        None
    } else {
        let digits = suffix.strip_prefix(':').ok_or(Rejection::BadRequest)?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Rejection::BadRequest);
        }
        Some(digits.parse::<u16>().map_err(|_| Rejection::BadRequest)?)
    };
    Ok(CheckedAuthority {
        host: host.to_owned(),
        ipv6,
        port,
    })
}

fn decode_early(encoded: &[u8], max_bytes: usize) -> Result<Vec<u8>, Rejection> {
    // 限额在分配/解码前检查，编码上界为 ceil(4 * max_bytes / 3)。
    let max_encoded = max_bytes
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(2))
        .map(|bytes| bytes / 3)
        .ok_or(Rejection::BadRequest)?;
    if encoded.len() > max_encoded
        || encoded.len() % 4 == 1
        || !encoded
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Rejection::BadRequest);
    }
    let decoded_len = (encoded.len() / 4)
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add((encoded.len() % 4).saturating_sub(1)))
        .ok_or(Rejection::BadRequest)?;
    if decoded_len > max_bytes {
        return Err(Rejection::BadRequest);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Rejection::BadRequest)?;
    if decoded.len() > max_bytes || URL_SAFE_NO_PAD.encode(&decoded).as_bytes() != encoded {
        return Err(Rejection::BadRequest);
    }
    Ok(decoded)
}

#[cfg(test)]
#[path = "upgrade_tests.rs"]
mod tests;
