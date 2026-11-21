//! TUIC v5 纯线格式编解码。
//!
//! 本模块只依赖 `std`，不进行任何 I/O、异步或环境访问，便于：
//! - 服务端在读取有界字节后做严格解析；
//! - `tests/tuic.rs` 通过 `#[path]` 直接编译本文件，并用独立参考编码器交叉验证。
//!
//! 协议要点（与 sing-quic@v0.7.2 的 `tuic` 包一致）：
//! - 所有多字节整数为大端；
//! - 每条流/每个数据报的前两字节固定为 `版本(5) + 命令`；
//! - 认证单向流载荷恰为 `UUID(16) + token(32)`；
//! - 地址族字节为 TUIC 私有的 `0x00 FQDN / 0x01 IPv4 / 0x02 IPv6 / 0xff Empty`，
//!   与 SOCKS5 的 `1/4/3` 不同；
//! - UDP 消息头为 `session u16 | packet u16 | fragment_total u8 | fragment_id u8 |
//!   data_len u16 | 地址 | 数据`。
//!
//! 所有长度都先做上界检查再分配；错误只返回类别，不回显任何输入内容。

use std::fmt;
use std::net::SocketAddr;

/// 协议版本。
pub const VERSION: u8 = 5;

/// 命令字。
pub const COMMAND_AUTHENTICATE: u8 = 0;
pub const COMMAND_CONNECT: u8 = 1;
pub const COMMAND_PACKET: u8 = 2;
pub const COMMAND_DISSOCIATE: u8 = 3;
pub const COMMAND_HEARTBEAT: u8 = 4;

/// 认证流载荷长度：`UUID(16) + token(32)`，不含 2 字节命令头。
pub const AUTH_BODY_LEN: usize = 16 + 32;
/// 认证单向流总长度，含 2 字节命令头。
pub const AUTH_FRAME_LEN: usize = 2 + AUTH_BODY_LEN;

/// UDP 消息固定头长度（不含 2 字节版本/命令头与地址）。
pub const UDP_FIXED_LEN: usize = 2 + 2 + 1 + 1 + 2;

/// 单个 `data_len` 字段能表达的最大载荷。
pub const MAX_UDP_DATA: usize = u16::MAX as usize;

/// 地址最大编码长度：FQDN 的 `1 + 1 + 255 + 2`。
pub const MAX_ADDRESS_LEN: usize = 1 + 1 + 255 + 2;

/// 一条 UDP 消息允许的最大分片数。上游字段为 `u8`，这里进一步收紧以限制重组内存。
pub const MAX_FRAGMENTS: u8 = 64;

/// 地址族。
pub const FAMILY_DOMAIN: u8 = 0x00;
pub const FAMILY_IPV4: u8 = 0x01;
pub const FAMILY_IPV6: u8 = 0x02;
pub const FAMILY_EMPTY: u8 = 0xff;

/// 命令枚举；未知命令在解析阶段即被拒绝。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Authenticate,
    Connect,
    Packet,
    Dissociate,
    Heartbeat,
}

impl Command {
    pub fn from_byte(value: u8) -> Option<Self> {
        match value {
            COMMAND_AUTHENTICATE => Some(Self::Authenticate),
            COMMAND_CONNECT => Some(Self::Connect),
            COMMAND_PACKET => Some(Self::Packet),
            COMMAND_DISSOCIATE => Some(Self::Dissociate),
            COMMAND_HEARTBEAT => Some(Self::Heartbeat),
            _ => None,
        }
    }

    // 供 tests/tuic.rs 通过 #[path] 引入使用；生产直接写 COMMAND_* 常量。
    #[allow(dead_code)]
    pub fn byte(self) -> u8 {
        match self {
            Self::Authenticate => COMMAND_AUTHENTICATE,
            Self::Connect => COMMAND_CONNECT,
            Self::Packet => COMMAND_PACKET,
            Self::Dissociate => COMMAND_DISSOCIATE,
            Self::Heartbeat => COMMAND_HEARTBEAT,
        }
    }
}

/// 线格式错误类别；不携带输入内容，避免把凭据或地址写入日志。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// 输入短于协议要求。
    Truncated,
    /// 声明长度与实际长度不一致。
    LengthMismatch,
    /// 版本不是 5。
    UnsupportedVersion,
    /// 命令字未知或在该载体上非法。
    UnknownCommand,
    /// 地址族未知。
    UnknownAddressFamily,
    /// 地址内容非法（空域名、非 ASCII 可打印域名等）。
    InvalidAddress,
    /// 长度或分片数超过本实现上限。
    Oversize,
    /// 分片编号/总数非法。
    InvalidFragment,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "TUIC 线格式被截断",
            Self::LengthMismatch => "TUIC 线格式长度不匹配",
            Self::UnsupportedVersion => "TUIC 版本不支持",
            Self::UnknownCommand => "TUIC 命令不支持",
            Self::UnknownAddressFamily => "TUIC 地址族不支持",
            Self::InvalidAddress => "TUIC 地址无效",
            Self::Oversize => "TUIC 字段超界",
            Self::InvalidFragment => "TUIC 分片信息无效",
        })
    }
}

impl std::error::Error for WireError {}

/// 解析后的地址。`Empty` 只允许出现在非首分片的 UDP 消息中。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireAddress {
    Empty,
    Ipv4 { octets: [u8; 4], port: u16 },
    Ipv6 { octets: [u8; 16], port: u16 },
    Domain { name: String, port: u16 },
}

impl WireAddress {
    /// 从套接字地址构造（只可能是 IP 形式）。
    pub fn from_socket(address: SocketAddr) -> Self {
        match address {
            SocketAddr::V4(value) => Self::Ipv4 {
                octets: value.ip().octets(),
                port: value.port(),
            },
            SocketAddr::V6(value) => Self::Ipv6 {
                octets: value.ip().octets(),
                port: value.port(),
            },
        }
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// 编码后的地址长度（含地址族字节）。
pub fn address_len(address: &WireAddress) -> usize {
    match address {
        WireAddress::Empty => 1,
        WireAddress::Ipv4 { .. } => 1 + 4 + 2,
        WireAddress::Ipv6 { .. } => 1 + 16 + 2,
        WireAddress::Domain { name, .. } => 1 + 1 + name.len() + 2,
    }
}

/// 编码地址；调用方保证 `out` 有界增长（最多追加 [`MAX_ADDRESS_LEN`] 字节）。
pub fn encode_address(address: &WireAddress, out: &mut Vec<u8>) -> Result<(), WireError> {
    match address {
        WireAddress::Empty => out.push(FAMILY_EMPTY),
        WireAddress::Ipv4 { octets, port } => {
            out.push(FAMILY_IPV4);
            out.extend_from_slice(octets);
            out.extend_from_slice(&port.to_be_bytes());
        }
        WireAddress::Ipv6 { octets, port } => {
            out.push(FAMILY_IPV6);
            out.extend_from_slice(octets);
            out.extend_from_slice(&port.to_be_bytes());
        }
        WireAddress::Domain { name, port } => {
            let bytes = name.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 || !bytes.iter().all(u8::is_ascii_graphic) {
                return Err(WireError::InvalidAddress);
            }
            out.push(FAMILY_DOMAIN);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

/// 解析地址，返回地址及其消耗的字节数。
pub fn decode_address(input: &[u8]) -> Result<(WireAddress, usize), WireError> {
    let family = *input.first().ok_or(WireError::Truncated)?;
    match family {
        FAMILY_EMPTY => Ok((WireAddress::Empty, 1)),
        FAMILY_IPV4 => {
            let bytes = input.get(..1 + 4 + 2).ok_or(WireError::Truncated)?;
            let octets = [bytes[1], bytes[2], bytes[3], bytes[4]];
            let port = u16::from_be_bytes([bytes[5], bytes[6]]);
            Ok((WireAddress::Ipv4 { octets, port }, 7))
        }
        FAMILY_IPV6 => {
            let bytes = input.get(..1 + 16 + 2).ok_or(WireError::Truncated)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[1..17]);
            let port = u16::from_be_bytes([bytes[17], bytes[18]]);
            Ok((WireAddress::Ipv6 { octets, port }, 19))
        }
        FAMILY_DOMAIN => {
            let length = usize::from(*input.get(1).ok_or(WireError::Truncated)?);
            if length == 0 {
                return Err(WireError::InvalidAddress);
            }
            let total = 2 + length + 2;
            let bytes = input.get(..total).ok_or(WireError::Truncated)?;
            let name = &bytes[2..2 + length];
            if !name.iter().all(u8::is_ascii_graphic) {
                return Err(WireError::InvalidAddress);
            }
            // `is_ascii_graphic` 已保证是合法 ASCII。
            let name = String::from_utf8(name.to_vec()).map_err(|_| WireError::InvalidAddress)?;
            let port = u16::from_be_bytes([bytes[2 + length], bytes[2 + length + 1]]);
            Ok((WireAddress::Domain { name, port }, total))
        }
        _ => Err(WireError::UnknownAddressFamily),
    }
}

/// 解析 2 字节命令头；只接受版本 5 与已知命令。
pub fn decode_command_header(input: &[u8]) -> Result<Command, WireError> {
    let version = *input.first().ok_or(WireError::Truncated)?;
    if version != VERSION {
        return Err(WireError::UnsupportedVersion);
    }
    let command = *input.get(1).ok_or(WireError::Truncated)?;
    Command::from_byte(command).ok_or(WireError::UnknownCommand)
}

/// 认证请求。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authenticate {
    pub uuid: [u8; 16],
    pub token: [u8; 32],
}

/// 编码认证帧（含 2 字节命令头）。
pub fn encode_authenticate(uuid: &[u8; 16], token: &[u8; 32]) -> [u8; AUTH_FRAME_LEN] {
    let mut frame = [0u8; AUTH_FRAME_LEN];
    frame[0] = VERSION;
    frame[1] = COMMAND_AUTHENTICATE;
    frame[2..18].copy_from_slice(uuid);
    frame[18..50].copy_from_slice(token);
    frame
}

/// 解析认证帧。线上认证流恰为 50 字节，任何多余字节都视为长度不匹配。
pub fn decode_authenticate(frame: &[u8]) -> Result<Authenticate, WireError> {
    if frame.len() < AUTH_FRAME_LEN {
        return Err(WireError::Truncated);
    }
    if frame.len() > AUTH_FRAME_LEN {
        return Err(WireError::LengthMismatch);
    }
    if decode_command_header(frame)? != Command::Authenticate {
        return Err(WireError::UnknownCommand);
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&frame[2..18]);
    let mut token = [0u8; 32];
    token.copy_from_slice(&frame[18..50]);
    Ok(Authenticate { uuid, token })
}

/// UDP 消息固定头（位于 2 字节版本/命令头之后）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpFixed {
    pub session_id: u16,
    pub packet_id: u16,
    pub fragment_total: u8,
    pub fragment_id: u8,
    pub data_len: u16,
}

pub fn decode_udp_fixed(bytes: &[u8]) -> Result<UdpFixed, WireError> {
    let bytes = bytes.get(..UDP_FIXED_LEN).ok_or(WireError::Truncated)?;
    Ok(UdpFixed {
        session_id: u16::from_be_bytes([bytes[0], bytes[1]]),
        packet_id: u16::from_be_bytes([bytes[2], bytes[3]]),
        fragment_total: bytes[4],
        fragment_id: bytes[5],
        data_len: u16::from_be_bytes([bytes[6], bytes[7]]),
    })
}

pub fn encode_udp_fixed(fixed: &UdpFixed) -> [u8; UDP_FIXED_LEN] {
    let mut bytes = [0u8; UDP_FIXED_LEN];
    bytes[0..2].copy_from_slice(&fixed.session_id.to_be_bytes());
    bytes[2..4].copy_from_slice(&fixed.packet_id.to_be_bytes());
    bytes[4] = fixed.fragment_total;
    bytes[5] = fixed.fragment_id;
    bytes[6..8].copy_from_slice(&fixed.data_len.to_be_bytes());
    bytes
}

/// 校验分片字段。`fragment_total == 1` 表示未分片；更小的 `total` 在 sing-box
/// 客户端中不会出现，这里按 fail-closed 拒绝。
pub fn validate_fragment(fragment_total: u8, fragment_id: u8) -> Result<(), WireError> {
    if fragment_total == 0 || fragment_total > MAX_FRAGMENTS {
        return Err(WireError::Oversize);
    }
    if fragment_total > 1 && fragment_id >= fragment_total {
        return Err(WireError::InvalidFragment);
    }
    Ok(())
}

/// 借用的 UDP 消息视图。
#[derive(Debug, PartialEq, Eq)]
pub struct UdpBody<'a> {
    pub session_id: u16,
    pub packet_id: u16,
    pub fragment_total: u8,
    pub fragment_id: u8,
    pub destination: WireAddress,
    pub payload: &'a [u8],
}

/// 解析固定头之后的 UDP 消息体，要求地址与数据恰好填满输入。
pub fn decode_udp_body(body: &[u8]) -> Result<UdpBody<'_>, WireError> {
    let fixed = decode_udp_fixed(body)?;
    validate_fragment(fixed.fragment_total, fixed.fragment_id)?;
    let (destination, used) = decode_address(&body[UDP_FIXED_LEN..])?;
    let start = UDP_FIXED_LEN + used;
    let end = start
        .checked_add(usize::from(fixed.data_len))
        .ok_or(WireError::Oversize)?;
    if end > body.len() {
        return Err(WireError::Truncated);
    }
    if end != body.len() {
        return Err(WireError::LengthMismatch);
    }
    Ok(UdpBody {
        session_id: fixed.session_id,
        packet_id: fixed.packet_id,
        fragment_total: fixed.fragment_total,
        fragment_id: fixed.fragment_id,
        destination,
        payload: &body[start..end],
    })
}

/// 解析完整 UDP 数据报（含 2 字节版本/命令头）。
// 供 tests/tuic.rs 与 fuzzing 入口使用；生产只走 decode_udp_body。
#[cfg_attr(not(feature = "fuzzing"), allow(dead_code))]
pub fn decode_udp_datagram(datagram: &[u8]) -> Result<UdpBody<'_>, WireError> {
    if decode_command_header(datagram)? != Command::Packet {
        return Err(WireError::UnknownCommand);
    }
    decode_udp_body(&datagram[2..])
}

/// 编码 UDP 消息体（不含 2 字节版本/命令头）。
pub fn encode_udp_body(
    session_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    destination: &WireAddress,
    payload: &[u8],
) -> Result<Vec<u8>, WireError> {
    if payload.len() > MAX_UDP_DATA {
        return Err(WireError::Oversize);
    }
    validate_fragment(fragment_total, fragment_id)?;
    let fixed = UdpFixed {
        session_id,
        packet_id,
        fragment_total,
        fragment_id,
        data_len: payload.len() as u16,
    };
    let mut out = Vec::with_capacity(UDP_FIXED_LEN + MAX_ADDRESS_LEN + payload.len());
    out.extend_from_slice(&encode_udp_fixed(&fixed));
    encode_address(destination, &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

/// 常量时间字节比较；长度不同直接返回 false（长度不是秘密）。
pub fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

/// 在已知 UUID 表中查找；遍历全部条目，不因命中提前返回。
#[cfg(test)]
pub fn lookup_uuid(known: &[[u8; 16]], candidate: &[u8; 16]) -> Option<usize> {
    let mut found = None;
    for (index, uuid) in known.iter().enumerate() {
        if ct_eq(uuid, candidate) {
            found = Some(index);
        }
    }
    found
}

/// 解析 UUID 文本。接受 32 位十六进制或标准 8-4-4-4-12 形式，
/// 也接受 `urn:uuid:` 前缀；其余形式一律拒绝。
pub fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let text = text
        .strip_prefix("urn:uuid:")
        .or_else(|| text.strip_prefix("URN:UUID:"))
        .unwrap_or(text);
    let bytes = text.as_bytes();
    let mut output = [0u8; 16];
    let mut written = 0usize;
    let mut high: Option<u8> = None;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == b'-' {
            // 只允许标准分隔位置，且不能连续或出现在首尾。
            if !matches!(index, 8 | 13 | 18 | 23) || high.is_some() {
                return None;
            }
            continue;
        }
        let value = hex_value(byte)?;
        match high {
            None => high = Some(value),
            Some(previous) => {
                if written >= output.len() {
                    return None;
                }
                output[written] = (previous << 4) | value;
                written += 1;
                high = None;
            }
        }
    }
    if high.is_some() || written != output.len() {
        return None;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_round_trip() {
        let address = WireAddress::Domain {
            name: "example.org".into(),
            port: 443,
        };
        let mut bytes = Vec::new();
        encode_address(&address, &mut bytes).unwrap();
        assert_eq!(bytes.as_slice(), b"\x00\x0bexample.org\x01\xbb".as_slice());
        assert_eq!(decode_address(&bytes).unwrap(), (address, bytes.len()));

        let address = WireAddress::Ipv4 {
            octets: [192, 0, 2, 7],
            port: 53,
        };
        let mut bytes = Vec::new();
        encode_address(&address, &mut bytes).unwrap();
        assert_eq!(bytes.as_slice(), b"\x01\xc0\x00\x02\x07\x00\x35".as_slice());
        assert_eq!(decode_address(&bytes).unwrap(), (address, bytes.len()));

        assert_eq!(
            decode_address(&[FAMILY_EMPTY]).unwrap(),
            (WireAddress::Empty, 1)
        );
    }

    #[test]
    fn address_rejects_overrun_and_invalid_domains() {
        assert_eq!(decode_address(&[]).unwrap_err(), WireError::Truncated);
        assert_eq!(
            decode_address(&[FAMILY_DOMAIN, 5, b'a']).unwrap_err(),
            WireError::Truncated
        );
        assert_eq!(
            decode_address(&[FAMILY_DOMAIN, 0]).unwrap_err(),
            WireError::InvalidAddress
        );
        assert_eq!(
            decode_address(&[FAMILY_DOMAIN, 2, b'a', b' ', 0, 80]).unwrap_err(),
            WireError::InvalidAddress
        );
        assert_eq!(
            decode_address(&[0x03, 1, 2, 3]).unwrap_err(),
            WireError::UnknownAddressFamily
        );
        let long = "a".repeat(256);
        assert_eq!(
            encode_address(
                &WireAddress::Domain {
                    name: long,
                    port: 1
                },
                &mut Vec::new()
            )
            .unwrap_err(),
            WireError::InvalidAddress
        );
    }

    #[test]
    fn uuid_parser_accepts_canonical_forms_only() {
        let expected = [0x11u8; 16];
        assert_eq!(
            parse_uuid("11111111-1111-1111-1111-111111111111"),
            Some(expected)
        );
        assert_eq!(
            parse_uuid("11111111111111111111111111111111"),
            Some(expected)
        );
        assert_eq!(
            parse_uuid("urn:uuid:11111111-1111-1111-1111-111111111111"),
            Some(expected)
        );
        assert!(parse_uuid("").is_none());
        assert!(parse_uuid("1111-1111").is_none());
        assert!(parse_uuid("11111111-1111-1111-1111-11111111111z").is_none());
        assert!(parse_uuid("11111111-1111-1111-1111-111111111111-").is_none());
    }

    #[test]
    fn authenticate_frame_is_strict() {
        let uuid = [0x11u8; 16];
        let token = [0x22u8; 32];
        let frame = encode_authenticate(&uuid, &token);
        assert_eq!(
            decode_authenticate(&frame).unwrap(),
            Authenticate { uuid, token }
        );
        assert!(decode_authenticate(&frame[..49]).is_err());
        let mut extra = frame.to_vec();
        extra.push(0);
        assert_eq!(
            decode_authenticate(&extra).unwrap_err(),
            WireError::LengthMismatch
        );
        let mut wrong = frame;
        wrong[0] = 4;
        assert_eq!(
            decode_authenticate(&wrong).unwrap_err(),
            WireError::UnsupportedVersion
        );
        let mut wrong = frame;
        wrong[1] = COMMAND_CONNECT;
        assert_eq!(
            decode_authenticate(&wrong).unwrap_err(),
            WireError::UnknownCommand
        );
    }

    #[test]
    fn command_header_rejects_unknown_versions_and_commands() {
        assert_eq!(
            decode_command_header(&[5, COMMAND_CONNECT]).unwrap(),
            Command::Connect
        );
        assert_eq!(
            decode_command_header(&[5, 9]).unwrap_err(),
            WireError::UnknownCommand
        );
        assert_eq!(
            decode_command_header(&[4, COMMAND_CONNECT]).unwrap_err(),
            WireError::UnsupportedVersion
        );
        assert_eq!(
            decode_command_header(&[5]).unwrap_err(),
            WireError::Truncated
        );
    }

    #[test]
    fn udp_body_is_exact_and_bounded() {
        let destination = WireAddress::Ipv4 {
            octets: [127, 0, 0, 1],
            port: 53,
        };
        let body = encode_udp_body(7, 9, 1, 0, &destination, b"payload").unwrap();
        let decoded = decode_udp_body(&body).unwrap();
        assert_eq!(decoded.session_id, 7);
        assert_eq!(decoded.packet_id, 9);
        assert_eq!(decoded.destination, destination);
        assert_eq!(decoded.payload, b"payload");

        let mut trailing = body.clone();
        trailing.push(0);
        assert_eq!(
            decode_udp_body(&trailing).unwrap_err(),
            WireError::LengthMismatch
        );
        let mut truncated = body;
        truncated.pop();
        assert_eq!(
            decode_udp_body(&truncated).unwrap_err(),
            WireError::Truncated
        );

        assert_eq!(
            encode_udp_body(0, 0, 0, 0, &destination, b"x").unwrap_err(),
            WireError::Oversize
        );
        assert_eq!(
            encode_udp_body(0, 0, 2, 2, &destination, b"x").unwrap_err(),
            WireError::InvalidFragment
        );
        let oversized = vec![0u8; MAX_UDP_DATA + 1];
        assert_eq!(
            encode_udp_body(0, 0, 1, 0, &destination, &oversized).unwrap_err(),
            WireError::Oversize
        );
    }

    #[test]
    fn uuid_lookup_rejects_unknown_user() {
        let known = [[0x11u8; 16], [0x33u8; 16]];
        assert_eq!(lookup_uuid(&known, &[0x11u8; 16]), Some(0));
        assert_eq!(lookup_uuid(&known, &[0x33u8; 16]), Some(1));
        assert_eq!(lookup_uuid(&known, &[0x22u8; 16]), None);
        assert!(ct_eq(b"token", b"token"));
        assert!(!ct_eq(b"token", b"tokeN"));
        assert!(!ct_eq(b"token", b"token "));
    }
}
