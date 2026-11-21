//! Hysteria2 线协议编解码（服务端视角）。
//!
//! 协议行为以本地只读上游为准：
//! - `sing-quic@v0.7.2-0.20261020082049-7e0a5869a5f4/hysteria2`
//! - `sing-box@v1.14.4/protocol/hysteria2` 与 `option/hysteria2.go`
//!
//! 本模块刻意不依赖 crate 内其它模块，`tests/hysteria2.rs` 可用 `#[path]`
//! 单独包含并测试，不需要真实网络。
//!
//! 编码格式（数值均为 QUIC varint，RFC 9000 §16）：
//!
//! ```text
//! TCP 请求（双向流首部）：
//!   0x401 | 地址长度 | 地址字节 | 填充长度 | 填充字节 | 载荷...
//!
//! TCP 响应：
//!   状态(1 字节，0=成功，1=失败) | 消息长度 | 消息 | 填充长度 | 填充 | 载荷...
//!
//! UDP DATAGRAM（`apernet/hysteria` `PROTOCOL.md`）：
//!   sessionID(4, 大端) | packetID(2, 大端) | fragmentID(1) |
//!   fragmentCount(1) | 目标长度 | 目标字符串 | 载荷...
//! ```

use std::io;

use http::{HeaderMap, HeaderValue, Method, Uri};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt};

/// HTTP/3 认证请求的 `:authority`。
pub(crate) const AUTH_HOST: &str = "hysteria";
/// HTTP/3 认证请求的 `:path`。
pub(crate) const AUTH_PATH: &str = "/auth";

pub(crate) const HEADER_AUTH: &str = "Hysteria-Auth";
pub(crate) const HEADER_UDP: &str = "Hysteria-UDP";
pub(crate) const HEADER_CC_RX: &str = "Hysteria-CC-RX";
pub(crate) const HEADER_PADDING: &str = "Hysteria-Padding";

/// 上游 `protocol.StatusAuthOK`；非标准但官方客户端按此判断认证成功。
pub(crate) const STATUS_AUTH_OK: u16 = 233;

/// TCP 请求帧类型；上游 `protocol.FrameTypeTCPRequest`。
pub(crate) const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// 与上游一致的 DoS 上限。
pub(crate) const MAX_ADDRESS_LENGTH: usize = 2048;
pub(crate) const MAX_MESSAGE_LENGTH: usize = 2048;
pub(crate) const MAX_PADDING_LENGTH: usize = 4096;
/// 单个 UDP 载荷上限；上游 `protocol.MaxUDPSize`。
pub(crate) const MAX_UDP_PAYLOAD: usize = 4096;
/// UDP 消息在不触发 QUIC 分片时的目标 MTU；上游 `udpMTU = 1200 - 3`。
pub(crate) const UDP_MTU: usize = 1200 - 3;
/// 单个 UDP 消息允许的最大分片数。上游载荷上限 4096 与 MTU 1197 组合
/// 最多产生 5 片；这里放宽到 16 仍能严格限制重组内存。
pub(crate) const MAX_FRAGMENTS: u8 = 16;
/// 认证密码长度上限，防止把任意长度的头部复制进内存。
pub(crate) const MAX_PASSWORD_LENGTH: usize = 4096;

/// QUIC varint 的 62 位上界。
pub(crate) const MAX_VARINT: u64 = (1u64 << 62) - 1;

/// 填充字符集与上游完全一致：大小写字母与数字。
const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn truncated(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, message)
}

/// 计算 QUIC varint 的编码长度；超出 62 位返回错误而不是截断。
pub(crate) fn varint_len(value: u64) -> io::Result<usize> {
    match value {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        1_073_741_824..=MAX_VARINT => Ok(8),
        _ => Err(invalid("varint 超出 62 位")),
    }
}

/// 把 varint 追加到缓冲区。
pub(crate) fn encode_varint(value: u64, output: &mut Vec<u8>) -> io::Result<()> {
    let length = varint_len(value)?;
    match length {
        1 => output.push(value as u8),
        2 => {
            output.push(((value >> 8) as u8) | 0x40);
            output.push(value as u8);
        }
        4 => {
            output.push(((value >> 24) as u8) | 0x80);
            output.push((value >> 16) as u8);
            output.push((value >> 8) as u8);
            output.push(value as u8);
        }
        _ => {
            output.push(((value >> 56) as u8) | 0xc0);
            output.push((value >> 48) as u8);
            output.push((value >> 40) as u8);
            output.push((value >> 32) as u8);
            output.push((value >> 24) as u8);
            output.push((value >> 16) as u8);
            output.push((value >> 8) as u8);
            output.push(value as u8);
        }
    }
    Ok(())
}

/// 从字节切片解码一个 varint，返回 `(值, 消耗字节数)`。
pub(crate) fn decode_varint(input: &[u8]) -> io::Result<(u64, usize)> {
    let first = *input.first().ok_or_else(|| truncated("varint 不完整"))?;
    let length = 1usize << (first >> 6);
    let rest = input
        .get(1..length)
        .ok_or_else(|| truncated("varint 不完整"))?;
    let mut value = u64::from(first & 0x3f);
    for byte in rest {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, length))
}

/// 从异步读取器读取一个 varint；最多读取 8 字节。
pub(crate) async fn read_varint<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first).await?;
    let length = 1usize << (first[0] >> 6);
    let mut value = u64::from(first[0] & 0x3f);
    if length > 1 {
        let mut rest = [0u8; 7];
        reader.read_exact(&mut rest[..length - 1]).await?;
        for byte in &rest[..length - 1] {
            value = (value << 8) | u64::from(*byte);
        }
    }
    Ok(value)
}

fn fill_random(output: &mut [u8]) -> io::Result<()> {
    aws_lc_rs::rand::fill(output).map_err(|_| io::Error::other("随机数生成失败"))
}

/// 生成 `[min, max_exclusive)` 长度的随机 ASCII 字母数字填充。
pub(crate) fn random_padding(min: usize, max_exclusive: usize) -> io::Result<Vec<u8>> {
    if min == 0 || min >= max_exclusive || max_exclusive > MAX_PADDING_LENGTH {
        return Err(invalid("填充长度范围无效"));
    }
    let mut selector = [0u8; 4];
    fill_random(&mut selector)?;
    let span = max_exclusive - min;
    let offset =
        usize::try_from(u32::from_be_bytes(selector)).map_err(|_| invalid("填充长度无效"))? % span;
    let mut padding = vec![0u8; min + offset];
    fill_random(&mut padding)?;
    for byte in &mut padding {
        *byte = PADDING_CHARS[usize::from(*byte) % PADDING_CHARS.len()];
    }
    Ok(padding)
}

/// 认证请求中与服务端相关的字段。
pub(crate) struct AuthRequest {
    pub password: Vec<u8>,
    pub rx: u64,
}

/// 认证响应中与服务端相关的字段。
// 以下客户端侧解码入口供 tests/hysteria2.rs 通过 #[path] 引入使用。
#[allow(dead_code)]
pub(crate) struct AuthResponse {
    pub udp_enabled: bool,
    pub rx: u64,
    pub rx_auto: bool,
}

/// 判断 HTTP/3 请求是否为 Hysteria2 认证端点。
///
/// 上游只比较 `Host` 与路径，不检查 scheme；这里保持一致，避免拒绝
/// 省略或改写 `:scheme` 的客户端。
pub(crate) fn is_auth_request(method: &Method, uri: &Uri) -> bool {
    method == Method::POST
        && uri.authority().map(http::uri::Authority::as_str) == Some(AUTH_HOST)
        && uri.path() == AUTH_PATH
}

/// 解析认证请求头。
///
/// 缺失或空密码一律拒绝（fail-closed）；`Hysteria-CC-RX` 缺失或非法按 0 处理，
/// 与上游 `strconv.ParseUint` 忽略错误一致。
pub(crate) fn parse_auth_request(headers: &HeaderMap) -> io::Result<AuthRequest> {
    let value = headers
        .get(HEADER_AUTH)
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "缺少 Hysteria-Auth"))?;
    let password = value.as_bytes();
    if password.is_empty() || password.len() > MAX_PASSWORD_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "认证凭据长度无效",
        ));
    }
    let rx = headers
        .get(HEADER_CC_RX)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or(0);
    Ok(AuthRequest {
        password: password.to_vec(),
        rx,
    })
}

/// 生成认证成功响应头（数字 `Hysteria-CC-RX`）。
///
/// `rx` 是**服务端接收带宽**（上游 `MaxRx`），单位 byte/s；0 表示未限制。
/// 保留该两参数形式便于既有测试与调用方使用。
pub(crate) fn auth_ok_headers(udp_enabled: bool, rx: u64) -> io::Result<HeaderMap> {
    auth_ok_headers_auto(udp_enabled, rx, false)
}

/// 生成认证成功响应头，支持上游的 `Hysteria-CC-RX: auto` 扩展。
///
/// `rx_auto` 对应上游 `IgnoreClientBandwidth`：服务端要求客户端自行探测
/// 带宽，而不是使用服务端配置的 `MaxRx`。`Hysteria-Padding` 的取值区间
/// 与上游一致。
pub(crate) fn auth_ok_headers_auto(
    udp_enabled: bool,
    rx: u64,
    rx_auto: bool,
) -> io::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert(
        HEADER_UDP,
        HeaderValue::from_static(if udp_enabled { "true" } else { "false" }),
    );
    let rx_text = if rx_auto {
        "auto".to_owned()
    } else {
        rx.to_string()
    };
    headers.insert(
        HEADER_CC_RX,
        HeaderValue::from_str(&rx_text).map_err(|_| invalid("CC-RX 编码失败"))?,
    );
    let padding = random_padding(256, 2048)?;
    headers.insert(
        HEADER_PADDING,
        HeaderValue::from_bytes(&padding).map_err(|_| invalid("填充编码失败"))?,
    );
    Ok(headers)
}

/// 解析认证响应头（用于测试与互操作核对）。
#[allow(dead_code)]
pub(crate) fn parse_auth_response(headers: &HeaderMap) -> AuthResponse {
    let udp_enabled = headers
        .get(HEADER_UDP)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.trim().parse::<bool>().ok())
        .unwrap_or(false);
    let (rx, rx_auto) = match headers
        .get(HEADER_CC_RX)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    {
        Some("auto") => (0, true),
        Some(text) => (text.parse::<u64>().unwrap_or(0), false),
        None => (0, false),
    };
    AuthResponse {
        udp_enabled,
        rx,
        rx_auto,
    }
}

/// 计算密码的 SHA-256 摘要。
///
/// 常量时间比较要求两侧长度相同；先做摘要可避免长度分支泄露密码长度。
pub(crate) fn digest_password(password: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(password);
    let mut output = [0u8; 32];
    for (target, source) in output.iter_mut().zip(digest.iter()) {
        *target = *source;
    }
    output
}

/// 对候选密码与所有已配置摘要执行常量时间比较，不因命中顺序提前返回。
// 供 tests/hysteria2.rs 通过 #[path] 使用；生产走 match_password_index。
#[allow(dead_code)]
pub(crate) fn match_password_digest(candidate: &[u8], expected: &[[u8; 32]]) -> bool {
    match_password_index(candidate, expected).is_some()
}

/// 返回首个命中的用户下标；比较次数与用户数无关。
pub(crate) fn match_password_index(candidate: &[u8], expected: &[[u8; 32]]) -> Option<usize> {
    let candidate = digest_password(candidate);
    let mut matched = 0u8;
    let mut index = 0usize;
    for (position, digest) in expected.iter().enumerate() {
        let hit = candidate.ct_eq(digest);
        if bool::from(hit) && matched == 0 {
            index = position;
        }
        matched |= hit.unwrap_u8();
    }
    (matched == 1).then_some(index)
}

/// 读取 TCP 请求地址（帧类型 0x401 已由调用方读取并校验）。
pub(crate) async fn read_tcp_request<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<String> {
    let address_length = read_varint(reader).await?;
    if address_length == 0 || address_length > MAX_ADDRESS_LENGTH as u64 {
        return Err(invalid("TCP 请求地址长度无效"));
    }
    let address_length = usize::try_from(address_length).map_err(|_| invalid("地址长度无效"))?;
    let mut address = vec![0u8; address_length];
    reader.read_exact(&mut address).await?;
    let padding_length = read_varint(reader).await?;
    if padding_length > MAX_PADDING_LENGTH as u64 {
        return Err(invalid("TCP 请求填充长度无效"));
    }
    skip_exact(reader, padding_length).await?;
    String::from_utf8(address).map_err(|_| invalid("TCP 请求地址不是 UTF-8"))
}

/// 同步解码 TCP 请求；`input` 从帧类型之后开始，返回 `(地址, 剩余载荷)`。
#[allow(dead_code)]
pub(crate) fn decode_tcp_request(input: &[u8]) -> io::Result<(String, &[u8])> {
    let (address_length, consumed) = decode_varint(input)?;
    if address_length == 0 || address_length > MAX_ADDRESS_LENGTH as u64 {
        return Err(invalid("TCP 请求地址长度无效"));
    }
    let address_length = usize::try_from(address_length).map_err(|_| invalid("地址长度无效"))?;
    let address_start = consumed;
    let address_end = address_start
        .checked_add(address_length)
        .ok_or_else(|| invalid("地址长度溢出"))?;
    let address = input
        .get(address_start..address_end)
        .ok_or_else(|| truncated("TCP 请求地址不完整"))?;
    let (padding_length, consumed) = decode_varint(
        input
            .get(address_end..)
            .ok_or_else(|| truncated("TCP 请求填充长度不完整"))?,
    )?;
    if padding_length > MAX_PADDING_LENGTH as u64 {
        return Err(invalid("TCP 请求填充长度无效"));
    }
    let padding_length = usize::try_from(padding_length).map_err(|_| invalid("填充长度无效"))?;
    let payload_start = address_end
        .checked_add(consumed)
        .and_then(|value| value.checked_add(padding_length))
        .ok_or_else(|| invalid("填充长度溢出"))?;
    let payload = input
        .get(payload_start..)
        .ok_or_else(|| truncated("TCP 请求填充不完整"))?;
    let address = std::str::from_utf8(address)
        .map_err(|_| invalid("TCP 请求地址不是 UTF-8"))?
        .to_owned();
    Ok((address, payload))
}

async fn skip_exact<R: AsyncRead + Unpin>(reader: &mut R, mut length: u64) -> io::Result<()> {
    let mut buffer = [0u8; 512];
    while length > 0 {
        let take = usize::try_from(length.min(buffer.len() as u64))
            .map_err(|_| invalid("填充长度无效"))?;
        reader.read_exact(&mut buffer[..take]).await?;
        length -= take as u64;
    }
    Ok(())
}

/// 编码 TCP 请求（含帧类型），供测试与客户端互操作核对使用。
pub(crate) fn encode_tcp_request(destination: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    if destination.is_empty() || destination.len() > MAX_ADDRESS_LENGTH || !destination.is_ascii() {
        return Err(invalid("TCP 目标地址无效"));
    }
    let padding = random_padding(64, 512)?;
    let mut output = Vec::with_capacity(8 + destination.len() + padding.len() + payload.len());
    encode_varint(FRAME_TYPE_TCP_REQUEST, &mut output)?;
    encode_varint(destination.len() as u64, &mut output)?;
    output.extend_from_slice(destination.as_bytes());
    encode_varint(padding.len() as u64, &mut output)?;
    output.extend_from_slice(&padding);
    output.extend_from_slice(payload);
    Ok(output)
}

/// 编码 TCP 响应；`payload` 会紧跟在填充之后。
pub(crate) fn encode_tcp_response(ok: bool, message: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    let message = message.as_bytes();
    let message = if message.len() > MAX_MESSAGE_LENGTH {
        &message[..MAX_MESSAGE_LENGTH]
    } else {
        message
    };
    let padding = random_padding(128, 1024)?;
    let mut output = Vec::with_capacity(1 + 8 + message.len() + padding.len() + payload.len());
    output.push(if ok { 0 } else { 1 });
    encode_varint(message.len() as u64, &mut output)?;
    output.extend_from_slice(message);
    encode_varint(padding.len() as u64, &mut output)?;
    output.extend_from_slice(&padding);
    output.extend_from_slice(payload);
    Ok(output)
}

/// 同步解码 TCP 响应；返回 `(是否成功, 错误消息)`。
#[allow(dead_code)]
pub(crate) fn decode_tcp_response(input: &[u8]) -> io::Result<(bool, String)> {
    let status = *input.first().ok_or_else(|| truncated("TCP 响应不完整"))?;
    let (message_length, consumed) = decode_varint(
        input
            .get(1..)
            .ok_or_else(|| truncated("TCP 响应消息长度不完整"))?,
    )?;
    if message_length > MAX_MESSAGE_LENGTH as u64 {
        return Err(invalid("TCP 响应消息长度无效"));
    }
    let message_length = usize::try_from(message_length).map_err(|_| invalid("消息长度无效"))?;
    let message_start = 1 + consumed;
    let message_end = message_start
        .checked_add(message_length)
        .ok_or_else(|| invalid("消息长度溢出"))?;
    let message = input
        .get(message_start..message_end)
        .ok_or_else(|| truncated("TCP 响应消息不完整"))?;
    let (padding_length, consumed) = decode_varint(
        input
            .get(message_end..)
            .ok_or_else(|| truncated("TCP 响应填充长度不完整"))?,
    )?;
    if padding_length > MAX_PADDING_LENGTH as u64 {
        return Err(invalid("TCP 响应填充长度无效"));
    }
    let padding_length = usize::try_from(padding_length).map_err(|_| invalid("填充长度无效"))?;
    let padding_end = message_end
        .checked_add(consumed)
        .and_then(|value| value.checked_add(padding_length))
        .ok_or_else(|| invalid("填充长度溢出"))?;
    if input.get(padding_end..).is_none() {
        return Err(truncated("TCP 响应填充不完整"));
    }
    let message = std::str::from_utf8(message)
        .map_err(|_| invalid("TCP 响应消息不是 UTF-8"))?
        .to_owned();
    Ok((status == 0, message))
}

/// 解析后的 UDP DATAGRAM 视图。
pub(crate) struct UdpMessage<'a> {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_total: u8,
    pub destination: &'a str,
    pub payload: &'a [u8],
}

/// 解码 UDP DATAGRAM；所有长度字段都受严格上限约束。
pub(crate) fn decode_udp_message(input: &[u8]) -> io::Result<UdpMessage<'_>> {
    let header = input
        .get(..8)
        .ok_or_else(|| truncated("UDP 消息头不完整"))?;
    let session_id = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let packet_id = u16::from_be_bytes([header[4], header[5]]);
    let fragment_id = header[6];
    let fragment_total = header[7];
    if fragment_total == 0 || fragment_id >= fragment_total {
        return Err(invalid("UDP 分片字段无效"));
    }
    let (destination_length, consumed) = decode_varint(
        input
            .get(8..)
            .ok_or_else(|| truncated("UDP 目标长度不完整"))?,
    )?;
    if destination_length == 0 || destination_length > MAX_ADDRESS_LENGTH as u64 {
        return Err(invalid("UDP 目标长度无效"));
    }
    let destination_length =
        usize::try_from(destination_length).map_err(|_| invalid("目标长度无效"))?;
    let destination_start = 8 + consumed;
    let destination_end = destination_start
        .checked_add(destination_length)
        .ok_or_else(|| invalid("目标长度溢出"))?;
    let destination = input
        .get(destination_start..destination_end)
        .ok_or_else(|| truncated("UDP 目标不完整"))?;
    let destination =
        std::str::from_utf8(destination).map_err(|_| invalid("UDP 目标不是 UTF-8"))?;
    let payload = input
        .get(destination_end..)
        .ok_or_else(|| truncated("UDP 载荷不完整"))?;
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(invalid("UDP 载荷过长"));
    }
    Ok(UdpMessage {
        session_id,
        packet_id,
        fragment_id,
        fragment_total,
        destination,
        payload,
    })
}

/// 编码单条 UDP DATAGRAM。
pub(crate) fn encode_udp_message(
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_total: u8,
    destination: &str,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    if destination.is_empty() || destination.len() > MAX_ADDRESS_LENGTH || !destination.is_ascii() {
        return Err(invalid("UDP 目标地址无效"));
    }
    if fragment_total == 0 || fragment_id >= fragment_total {
        return Err(invalid("UDP 分片字段无效"));
    }
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(invalid("UDP 载荷过长"));
    }
    let mut output = Vec::with_capacity(8 + 2 + destination.len() + payload.len());
    output.extend_from_slice(&session_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.push(fragment_id);
    output.push(fragment_total);
    encode_varint(destination.len() as u64, &mut output)?;
    output.extend_from_slice(destination.as_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

/// 按 MTU 把一条 UDP 载荷切分为一个或多个 DATAGRAM。
///
/// 切分后每片都带完整的目标地址；上游客户端用 `(sessionID, packetID)`
/// 重组，因此同一消息的所有分片必须使用相同 packetID。
pub(crate) fn fragment_udp_message(
    session_id: u32,
    packet_id: u16,
    destination: &str,
    payload: &[u8],
    mtu: usize,
) -> io::Result<Vec<Vec<u8>>> {
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(invalid("UDP 载荷过长"));
    }
    if destination.is_empty() || destination.len() > MAX_ADDRESS_LENGTH || !destination.is_ascii() {
        return Err(invalid("UDP 目标地址无效"));
    }
    let header = 8usize
        .checked_add(varint_len(destination.len() as u64)?)
        .and_then(|value| value.checked_add(destination.len()))
        .ok_or_else(|| invalid("UDP 头长度溢出"))?;
    if mtu <= header {
        return Err(invalid("UDP MTU 小于消息头"));
    }
    let chunk_size = mtu - header;
    let total = if payload.is_empty() {
        1
    } else {
        payload.len().div_ceil(chunk_size)
    };
    if total > usize::from(MAX_FRAGMENTS) {
        return Err(invalid("UDP 分片数超限"));
    }
    let total = u8::try_from(total).map_err(|_| invalid("分片数超限"))?;
    let mut fragments = Vec::with_capacity(usize::from(total));
    if payload.is_empty() {
        fragments.push(encode_udp_message(
            session_id,
            packet_id,
            0,
            1,
            destination,
            payload,
        )?);
        return Ok(fragments);
    }
    for (index, chunk) in payload.chunks(chunk_size).enumerate() {
        let index = u8::try_from(index).map_err(|_| invalid("分片序号超限"))?;
        fragments.push(encode_udp_message(
            session_id,
            packet_id,
            index,
            total,
            destination,
            chunk,
        )?);
    }
    Ok(fragments)
}

/// 解析 `host:port`，与 Go `net.SplitHostPort` / sing `Socksaddr.String()`
/// 的格式一致：域名与 IPv4 为 `host:port`，IPv6 为 `[addr]:port`。
pub(crate) fn parse_host_port(text: &str) -> io::Result<(String, u16)> {
    if text.is_empty() || text.len() > MAX_ADDRESS_LENGTH || !text.is_ascii() {
        return Err(invalid("目标地址无效"));
    }
    let (host, port_text) = if let Some(rest) = text.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| invalid("IPv6 目标地址缺少右括号"))?;
        let port_text = rest
            .strip_prefix(':')
            .ok_or_else(|| invalid("IPv6 目标地址缺少端口"))?;
        (host, port_text)
    } else {
        let (host, port_text) = text
            .rsplit_once(':')
            .ok_or_else(|| invalid("目标地址缺少端口"))?;
        if host.contains(':') {
            return Err(invalid("IPv6 目标地址必须使用方括号"));
        }
        (host, port_text)
    };
    if host.is_empty() || host.len() > 255 {
        return Err(invalid("目标主机名长度无效"));
    }
    // 不支持的 IPv6 zone 会让 IpAddr 解析失败并被误当成域名，直接拒绝。
    if !host
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'%')
    {
        return Err(invalid("目标主机名包含无效字符"));
    }
    if port_text.is_empty() || !port_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("目标端口无效"));
    }
    let port = port_text
        .parse::<u16>()
        .map_err(|_| invalid("目标端口无效"))?;
    Ok((host.to_owned(), port))
}

/// 拼装 `host:port`；IPv6 自动加方括号。
pub(crate) fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
