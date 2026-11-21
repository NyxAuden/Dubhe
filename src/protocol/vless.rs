use std::{
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr},
};

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    config::{VlessFlow, VlessUser, parse_uuid},
    session::{Command, Host, Request, Target},
};

#[derive(Debug)]
pub enum Accepted {
    Single(Request),
    /// 命令 3：完整 Mux；TCP/UDP 由 Mux 帧的 network 字段决定。
    Mux {
        user: String,
    },
    /// 命令 4：反向 Mux portal 隧道。
    Reverse {
        user: String,
    },
}

/// UUID 只交给 Vision codec，不进入公共会话或 Debug 输出。
pub struct FlowAccepted {
    pub accepted: Accepted,
    pub vision: Option<[u8; 16]>,
}

impl fmt::Debug for FlowAccepted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlowAccepted")
            .field("accepted", &self.accepted)
            .field("vision", &self.vision.map(|_| "[REDACTED]"))
            .finish()
    }
}

/// 基础入口只返回单一请求，无法表示 Mux；运行层应改用带 Mux 的入口。
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    users: &[VlessUser],
) -> io::Result<Request> {
    match handshake_with_xudp(io, users, false).await? {
        Accepted::Single(request) => Ok(request),
        Accepted::Mux { .. } | Accepted::Reverse { .. } => {
            // 保持旧入口失败即关闭的既有语义。
            let _ = io.shutdown().await;
            Err(invalid("基础入口不支持 Mux/反向 Mux"))
        }
    }
}

/// 普通入口仅接受空 addons，不会因用户配置而隐式开启 Vision。
///
/// `xudp` 参数保留用于既有调用方签名；命令 3 一律解析为 Mux，UDP 会话的
/// 准入由运行层传入 `mux::serve*` 的 `allow_udp` 决定。
pub async fn handshake_with_xudp<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    users: &[VlessUser],
    xudp: bool,
) -> io::Result<Accepted> {
    Ok(accept_request(io, users, xudp, None).await?.accepted)
}

/// 整体可丢弃的 WS 认证失败不等待对端 Close；旧 TLS 入口保留原关闭策略。
pub(crate) async fn read_plain_request<R: AsyncRead + Unpin>(
    io: &mut R,
    users: &[VlessUser],
    xudp: bool,
) -> io::Result<Accepted> {
    Ok(read_request(io, users, xudp, None).await?.accepted)
}

/// tls13 必须来自已经完成的外层 TLS 握手，而非客户端声明或用户配置。
pub async fn handshake_with_flow<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    users: &[VlessUser],
    xudp: bool,
    tls13: bool,
) -> io::Result<FlowAccepted> {
    accept_request(io, users, xudp, Some(tls13)).await
}

async fn accept_request<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    users: &[VlessUser],
    xudp: bool,
    flow_tls13: Option<bool>,
) -> io::Result<FlowAccepted> {
    let result = read_request(io, users, xudp, flow_tls13).await;
    if result.is_err() {
        let _ = io.shutdown().await;
    }
    result
}

async fn read_request<R: AsyncRead + Unpin>(
    io: &mut R,
    users: &[VlessUser],
    _xudp: bool,
    flow_tls13: Option<bool>,
) -> io::Result<FlowAccepted> {
    if io.read_u8().await? != 0 {
        return Err(invalid("不支持的 VLESS 版本"));
    }
    let mut supplied = [0; 16];
    io.read_exact(&mut supplied).await?;
    let mut accepted = Choice::from(0);
    let mut selected = 0u64;
    // 遍历全部用户比较完整身份，匹配位置不改变比较和选择的执行路径。
    for (index, user) in users.iter().enumerate() {
        let expected = parse_uuid(&user.uuid);
        let matches = supplied.ct_eq(&expected.unwrap_or([0; 16]))
            & Choice::from(u8::from(expected.is_some()));
        selected = u64::conditional_select(&selected, &(index as u64), matches & !accepted);
        accepted |= matches;
    }
    if !bool::from(accepted) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VLESS 认证失败",
        ));
    }
    let user = &users[selected as usize];
    let length = usize::from(io.read_u8().await?);
    // 普通账户及旧入口不解释非空 addons，更不能删除它后当作空 flow。
    if length != 0 && (user.flow == VlessFlow::None || flow_tls13.is_none()) {
        return Err(invalid("不支持非空 VLESS addons"));
    }
    let mut addons = [0; 255];
    io.read_exact(&mut addons[..length]).await?;
    let flow = parse_addons(&addons[..length])?;
    let command = io.read_u8().await?;
    // 命令 3 的结构固定为 Mux（无目标字段），不再由 xudp 开关决定是否接受；
    // xudp 仅在运行层门控 Mux 内的 UDP 会话。
    if !matches!(command, 1..=4) {
        return Err(invalid("不支持的 VLESS 命令"));
    }
    let vision = match (user.flow, flow, command) {
        (VlessFlow::None, VlessFlow::None, _) | (VlessFlow::Vision, VlessFlow::None, 2..=4) => None,
        (VlessFlow::Vision, VlessFlow::Vision, 1 | 3..=4) if flow_tls13 == Some(true) => {
            Some(supplied)
        }
        _ => return Err(invalid("VLESS flow、命令或 TLS 版本不匹配")),
    };
    let accepted = if command == 4 {
        Accepted::Reverse {
            user: user.name.clone(),
        }
    } else if command == 3 {
        // 命令 3 没有基础目标字段；由 Mux 层逐帧解析 network 与目标。
        Accepted::Mux {
            user: user.name.clone(),
        }
    } else {
        let target = read_target(io).await?;
        Accepted::Single(Request {
            command: if command == 1 {
                Command::Connect
            } else {
                Command::UdpAssociate
            },
            target,
            user: Some(user.name.clone()),
        })
    };
    Ok(FlowAccepted { accepted, vision })
}

/// 有限 protobuf 子集：仅规范的字段 1 / wire type 2，且只允许出现一次。
fn parse_addons(addons: &[u8]) -> io::Result<VlessFlow> {
    if addons.is_empty() {
        return Ok(VlessFlow::None);
    }
    if addons.len() > 255 || addons[0] != 0x0a {
        return Err(invalid("无效 VLESS addons"));
    }
    // 本子集只有空 flow 或 16 字节 Vision，合法 key 和 length 均为单字节。
    // 续位编码要么不规范，要么指向不支持的 flow/越界长度，均拒绝。
    let length = *addons.get(1).ok_or_else(|| invalid("无效 VLESS addons"))?;
    if length & 0x80 != 0 || addons.len() != usize::from(length) + 2 {
        return Err(invalid("无效 VLESS addons"));
    }
    match &addons[2..] {
        b"" => Ok(VlessFlow::None),
        b"xtls-rprx-vision" => Ok(VlessFlow::Vision),
        _ => Err(invalid("不支持的 VLESS flow")),
    }
}

pub(crate) async fn read_target<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Target> {
    // VLESS 是端口在前、地址在后；地址类型与 SOCKS5 不同，不能复用其 codec。
    let port = r.read_u16().await?;
    let host = match r.read_u8().await? {
        1 => {
            let mut octets = [0; 4];
            r.read_exact(&mut octets).await?;
            Host::Ip(Ipv4Addr::from(octets).into())
        }
        2 => {
            let length = usize::from(r.read_u8().await?);
            if length == 0 {
                return Err(invalid("无效 VLESS 目标域名"));
            }
            let mut bytes = [0; 255];
            let domain = &mut bytes[..length];
            r.read_exact(domain).await?;
            // 与现有目标地址规则一致，国际化域名使用 ASCII A-label。
            if !domain.iter().all(u8::is_ascii_graphic) {
                return Err(invalid("无效 VLESS 目标域名"));
            }
            let domain = std::str::from_utf8(domain).map_err(|_| invalid("无效 VLESS 目标域名"))?;
            Host::Domain(domain.to_owned())
        }
        3 => {
            let mut octets = [0; 16];
            r.read_exact(&mut octets).await?;
            Host::Ip(Ipv6Addr::from(octets).into())
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "不支持的 VLESS 地址类型",
            ));
        }
    };
    Ok(Target { host, port })
}

/// 运行层在目标连接或 UDP 关联准备成功后调用一次；版本 0、空 addons。
pub async fn reply<W: AsyncWrite + Unpin>(w: &mut W) -> io::Result<()> {
    w.write_all(&[0, 0]).await?;
    w.flush().await
}

/// 固定目标 UDP 仅有长度和载荷；先检查限额，再分配并完整读取单帧。
/// 空帧返回空 Vec，由运行层消费、丢弃并计数。
pub async fn read_datagram<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> io::Result<Vec<u8>> {
    let length = usize::from(r.read_u16().await?);
    if length > max {
        return Err(invalid("VLESS 数据报超过长度上限"));
    }
    let mut payload = vec![0; length];
    r.read_exact(&mut payload).await?;
    Ok(payload)
}

pub fn encode_datagram(payload: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "VLESS 数据报超过线协议长度上限",
        )
    })?;
    let mut bytes = Vec::with_capacity(2 + payload.len());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::test_io::Wire;

    // 独立手写线字节，不通过配置 UUID 解析器或服务端 codec 构造请求。
    const UUID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn users() -> Vec<VlessUser> {
        vec![
            VlessUser {
                name: "first".into(),
                uuid: "00000000-0000-0000-0000-000000000000".into(),
                flow: VlessFlow::None,
            },
            VlessUser {
                name: "alice".into(),
                uuid: "00112233-4455-6677-8899-AABBCCDDEEFF".into(),
                flow: VlessFlow::None,
            },
            VlessUser {
                name: "last".into(),
                uuid: "ffffffff-ffff-ffff-ffff-ffffffffffff".into(),
                flow: VlessFlow::None,
            },
        ]
    }

    fn request(command: u8, target: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0];
        bytes.extend_from_slice(&UUID);
        bytes.extend_from_slice(&[0, command]);
        bytes.extend_from_slice(target);
        bytes.extend_from_slice(payload);
        bytes
    }

    // 独立金样：flow 是 16 个 ASCII 字节，addons 总长是 18（不是字符串长 18）。
    const VISION_ADDONS: &[u8; 18] = b"\x0a\x10xtls-rprx-vision";

    fn flow_users() -> Vec<VlessUser> {
        let mut users = users();
        users[1].flow = VlessFlow::Vision;
        users
    }

    fn request_with_addons(command: u8, addons: &[u8], target: &[u8], body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0];
        bytes.extend_from_slice(&UUID);
        bytes.push(u8::try_from(addons.len()).unwrap());
        bytes.extend_from_slice(addons);
        bytes.push(command);
        bytes.extend_from_slice(target);
        bytes.extend_from_slice(body);
        bytes
    }

    fn targets() -> [(Vec<u8>, Host); 3] {
        [
            (
                vec![0x01, 0xbb, 1, 192, 0, 2, 7],
                Host::Ip("192.0.2.7".parse().unwrap()),
            ),
            (
                b"\x01\xbb\x02\x0bexample.org".to_vec(),
                Host::Domain("example.org".into()),
            ),
            (
                vec![
                    0x01, 0xbb, 3, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ],
                Host::Ip("2001:db8::1".parse().unwrap()),
            ),
        ]
    }

    #[test]
    fn addons_golden_subset_and_malformed_encodings() {
        assert_eq!(b"xtls-rprx-vision".len(), 16);
        assert_eq!(VISION_ADDONS.len(), 18);
        assert_eq!(&VISION_ADDONS[..2], &[0x0a, 0x10]);
        assert_eq!(parse_addons(&[]).unwrap(), VlessFlow::None);
        assert_eq!(parse_addons(&[0x0a, 0]).unwrap(), VlessFlow::None);
        assert_eq!(parse_addons(VISION_ADDONS).unwrap(), VlessFlow::Vision);
        for addons in malformed_addons() {
            assert!(parse_addons(&addons).is_err(), "addons={addons:?}");
        }
    }

    fn malformed_addons() -> Vec<Vec<u8>> {
        let mut duplicate = VISION_ADDONS.to_vec();
        duplicate.extend_from_slice(VISION_ADDONS);
        let mut trailing_unknown = VISION_ADDONS.to_vec();
        trailing_unknown.extend_from_slice(&[0x10, 0]);
        let mut noncanonical_key = vec![0x8a, 0, 0x10];
        noncanonical_key.extend_from_slice(b"xtls-rprx-vision");
        let mut noncanonical_length = vec![0x0a, 0x90, 0];
        noncanonical_length.extend_from_slice(b"xtls-rprx-vision");
        vec![
            vec![0],                            // 禁止 field 0。
            vec![0x08, 0],                      // 字段 1 错误 wire type。
            vec![0x0b, 0x0c],                   // 不支持 group。
            vec![0x12, 0],                      // 未知字段 2。
            vec![0x0a],                         // 缺失长度。
            vec![0x0a, 1],                      // 缺失正文。
            vec![0x0a, 0x10, b'x'],             // 声明长度超过边界。
            vec![0x0a, 0, 0],                   // 多余字节。
            vec![0x0a, 0, 0x0a, 0],             // 重复空字段。
            vec![0x0a, 0x80, 0],                // 非规范零长度。
            vec![0x0a, 0x80],                   // 截断 varint。
            vec![0x0a, 0xff, 0xff, 0xff, 0x7f], // 超限 varint。
            vec![0xff; 255],                    // 最大 addons 也有限拒绝。
            vec![0x0a, 1, 0xff],                // 非 UTF-8 flow。
            b"\x0a\x03bad".to_vec(),
            b"\x0a\x10XTLS-RPRX-VISION".to_vec(),
            b"\x0a\x17xtls-rprx-vision-udp443".to_vec(),
            duplicate,
            trailing_unknown,
            noncanonical_key,
            noncanonical_length,
        ]
    }

    #[tokio::test]
    async fn full_flow_command_tls_xudp_admission_matrix_has_no_error_response() {
        // 覆盖全部 256 个命令字节、两种用户、空/显式空/Vision/未知请求 flow，
        // 两个实际 TLS 版本、xudp 开关和逐字节/合并输入。命令 3 与 xudp 无关，
        // 该开关只影响运行层对 Mux 内 UDP 会话的门控。
        for user_flow in [VlessFlow::None, VlessFlow::Vision] {
            let mut users = users();
            users[1].flow = user_flow;
            for (addons, request_flow) in [
                (&b""[..], Some(VlessFlow::None)),
                (&b"\x0a\x00"[..], Some(VlessFlow::None)),
                (&VISION_ADDONS[..], Some(VlessFlow::Vision)),
                (&b"\x0a\x0bflow-secret"[..], None),
            ] {
                for command in 0..=255u8 {
                    for tls13 in [false, true] {
                        for xudp in [false, true] {
                            let allowed_command = matches!(command, 1..=4);
                            let allowed = allowed_command
                                && match (user_flow, request_flow, command) {
                                    (VlessFlow::None, Some(VlessFlow::None), _) => {
                                        addons.is_empty()
                                    }
                                    (VlessFlow::Vision, Some(VlessFlow::None), 2..=4) => true,
                                    (VlessFlow::Vision, Some(VlessFlow::Vision), 1 | 3..=4) => {
                                        tls13
                                    }
                                    _ => false,
                                };
                            for fragmented in [false, true] {
                                let target = if matches!(command, 3 | 4) {
                                    &b""[..]
                                } else {
                                    &b"\x01\xbb\x01\xc0\x00\x02\x07"[..]
                                };
                                let mut wire = Wire::new(request_with_addons(
                                    command,
                                    addons,
                                    target,
                                    b"\0body-secret",
                                ));
                                if fragmented {
                                    wire = wire.fragmented();
                                }
                                let result =
                                    handshake_with_flow(&mut wire, &users, xudp, tls13).await;
                                assert_eq!(
                                    result.is_ok(),
                                    allowed,
                                    "user={user_flow:?} request={request_flow:?} addons_len={} command={command} tls13={tls13} xudp={xudp} fragmented={fragmented}",
                                    addons.len()
                                );
                                assert!(wire.output.is_empty());
                                if let Ok(result) = result {
                                    assert_eq!(
                                        result.vision,
                                        if request_flow == Some(VlessFlow::Vision) {
                                            Some(UUID)
                                        } else {
                                            None
                                        }
                                    );
                                    match result.accepted {
                                        Accepted::Single(request) => {
                                            assert!(matches!(command, 1 | 2));
                                            assert_eq!(
                                                request.command,
                                                if command == 1 {
                                                    Command::Connect
                                                } else {
                                                    Command::UdpAssociate
                                                }
                                            );
                                            assert_eq!(request.user.as_deref(), Some("alice"));
                                            assert_eq!(
                                                request.target,
                                                Target {
                                                    host: Host::Ip("192.0.2.7".parse().unwrap()),
                                                    port: 443
                                                }
                                            );
                                        }
                                        Accepted::Mux { user } => {
                                            assert_eq!(command, 3);
                                            assert_eq!(user, "alice");
                                        }
                                        Accepted::Reverse { user } => {
                                            assert_eq!(command, 4);
                                            assert_eq!(user, "alice");
                                        }
                                    }
                                    assert!(!wire.closed);
                                    assert_eq!(wire.remaining(), b"\0body-secret");
                                } else {
                                    assert!(wire.closed);
                                    let mut untouched = target.to_vec();
                                    untouched.extend_from_slice(b"\0body-secret");
                                    // 失败先于读取目标字段；握手层不拥有任何拨号能力。
                                    assert!(wire.remaining().ends_with(&untouched));
                                    let error = result.unwrap_err();
                                    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                                    assert!(!error.to_string().contains("flow-secret"));
                                    assert!(!error.to_string().contains("body-secret"));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn vision_golden_requests_preserve_all_targets_body_and_redact_uuid() {
        for (target, host) in targets() {
            for fragmented in [false, true] {
                let bytes = request_with_addons(1, VISION_ADDONS, &target, b"\0vision-body\xff");
                assert_eq!(bytes[17], 18);
                assert_eq!(&bytes[18..36], VISION_ADDONS);
                let mut wire = Wire::new(bytes);
                if fragmented {
                    wire = wire.fragmented();
                }
                let accepted = handshake_with_flow(&mut wire, &flow_users(), false, true)
                    .await
                    .unwrap();
                assert_eq!(accepted.vision, Some(UUID));
                for rendered in [format!("{accepted:?}"), format!("{accepted:#?}")] {
                    assert!(rendered.contains("[REDACTED]"));
                    assert!(!rendered.contains("00112233-4455-6677-8899"));
                    assert!(!rendered.contains(&format!("{UUID:?}")));
                }
                let Accepted::Single(request) = accepted.accepted else {
                    panic!()
                };
                assert_eq!(
                    request.target,
                    Target {
                        host: host.clone(),
                        port: 443
                    }
                );
                assert_eq!(wire.remaining(), b"\0vision-body\xff");
                assert!(wire.output.is_empty() && !wire.closed);
            }
        }
    }

    #[tokio::test]
    async fn malformed_addons_and_all_vision_request_truncations_fail_closed() {
        let target = b"\x01\xbb\x01\x7f\x00\x00\x01";
        for addons in malformed_addons() {
            for fragmented in [false, true] {
                let mut wire = Wire::new(request_with_addons(1, &addons, target, b"secret-body"));
                if fragmented {
                    wire = wire.fragmented();
                }
                let error = handshake_with_flow(&mut wire, &flow_users(), true, true)
                    .await
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(wire.closed && wire.output.is_empty());
                assert!(!error.to_string().contains("secret-body"));
                assert!(!error.to_string().contains("xtls-rprx-"));
            }
        }
        for command in [1, 3] {
            let target = if command == 3 { &b""[..] } else { &target[..] };
            let bytes = request_with_addons(command, VISION_ADDONS, target, &[]);
            for end in 0..bytes.len() {
                let mut wire = Wire::new(bytes[..end].to_vec()).fragmented();
                assert_eq!(
                    handshake_with_flow(&mut wire, &flow_users(), true, true)
                        .await
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::UnexpectedEof,
                    "command={command} end={end}"
                );
                assert!(wire.closed && wire.output.is_empty());
            }
        }
        // 最大 255 字节长度必须完整到达，再解析；不能越界吞掉 command/body。
        for end in 0..255 {
            let mut bytes = vec![0];
            bytes.extend_from_slice(&UUID);
            bytes.push(255);
            bytes.extend_from_slice(&vec![0x0a; end]);
            let mut wire = Wire::new(bytes).fragmented();
            assert_eq!(
                handshake_with_flow(&mut wire, &flow_users(), true, true)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert!(wire.closed && wire.output.is_empty());
        }
    }

    #[tokio::test]
    async fn authentication_precedes_addons_and_selects_flow_at_every_position() {
        for supplied in [UUID, [0; 16]] {
            let mut configured = flow_users();
            configured[0].uuid = "invalid-uuid-secret".into();
            for index in 0..16 {
                let mut bytes = vec![0];
                let mut wrong = supplied;
                wrong[index] ^= 1;
                bytes.extend_from_slice(&wrong);
                bytes.extend_from_slice(b"\xffmalformed-addons-secret");
                let mut wire = Wire::new(bytes).fragmented();
                let error = handshake_with_flow(&mut wire, &configured, true, true)
                    .await
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
                assert_eq!(error.to_string(), "VLESS 认证失败");
                assert_eq!(wire.remaining(), b"\xffmalformed-addons-secret");
                assert!(wire.closed && wire.output.is_empty());
            }
        }
        // 无效配置 UUID 的零值 fallback 不能认证全零 wire UUID。
        let mut invalid = flow_users();
        invalid[0].uuid = "invalid-uuid-secret".into();
        let mut bytes = request_with_addons(1, VISION_ADDONS, b"\x00\x50\x01\x7f\x00\x00\x01", &[]);
        bytes[1..17].fill(0);
        let mut wire = Wire::new(bytes);
        assert_eq!(
            handshake_with_flow(&mut wire, &invalid, true, true)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(wire.closed && wire.output.is_empty());

        let mut configured = flow_users();
        for _ in 0..configured.len() {
            let mut wire = Wire::new(request_with_addons(
                1,
                VISION_ADDONS,
                b"\x00\x50\x01\x7f\x00\x00\x01",
                &[],
            ));
            let accepted = handshake_with_flow(&mut wire, &configured, false, true)
                .await
                .unwrap();
            assert_eq!(accepted.vision, Some(UUID));
            assert!(
                matches!(accepted.accepted, Accepted::Single(Request { user: Some(ref user), .. }) if user == "alice")
            );
            configured.rotate_left(1);
        }
    }

    #[tokio::test]
    async fn legacy_wrappers_never_enable_vision_or_accept_nonempty_addons() {
        for addons in [&VISION_ADDONS[..], &b"\x0a\x00"[..]] {
            for configured in [users(), flow_users()] {
                for command in [1, 2, 3] {
                    let target = if command == 3 {
                        &b""[..]
                    } else {
                        &b"\x00\x50\x01\x7f\x00\x00\x01"[..]
                    };
                    let bytes = request_with_addons(command, addons, target, &[]);
                    let mut wire = Wire::new(bytes.clone());
                    assert!(handshake(&mut wire, &configured).await.is_err());
                    assert!(wire.closed && wire.output.is_empty());
                    let mut wire = Wire::new(bytes);
                    assert!(
                        handshake_with_xudp(&mut wire, &configured, true)
                            .await
                            .is_err()
                    );
                    assert!(wire.closed && wire.output.is_empty());
                }
            }
        }
    }

    #[tokio::test]
    async fn fragmented_and_combined_requests_preserve_payload_for_all_targets() {
        for (target, host) in targets() {
            for (command, expected) in [(1, Command::Connect), (2, Command::UdpAssociate)] {
                for fragmented in [false, true] {
                    let mut io = Wire::new(request(command, &target, b"\0payload\r\n"));
                    if fragmented {
                        io = io.fragmented();
                    }
                    let parsed = handshake(&mut io, &users()).await.unwrap();
                    assert_eq!(parsed.command, expected);
                    assert_eq!(
                        parsed.target,
                        Target {
                            host: host.clone(),
                            port: 443
                        }
                    );
                    assert_eq!(parsed.user.as_deref(), Some("alice"));
                    assert_eq!(io.remaining(), b"\0payload\r\n");
                    assert!(io.output.is_empty());
                    assert!(!io.closed);
                }
            }
        }
    }

    #[tokio::test]
    async fn buffered_request_keeps_prefetched_payload_and_response_is_exact() {
        let wire = Wire::new(request(1, &[0, 80, 1, 127, 0, 0, 1], b"first-payload"));
        let mut io = tokio::io::BufStream::new(wire);
        handshake(&mut io, &users()).await.unwrap();
        let mut payload = Vec::new();
        io.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"first-payload");
        assert!(io.get_ref().output.is_empty());
        reply(&mut io).await.unwrap();
        io.flush().await.unwrap();
        assert_eq!(io.get_ref().output, [0, 0]);
    }

    #[tokio::test]
    async fn command3_is_mux_regardless_of_xudp_and_does_not_consume_frames() {
        let bytes = request(3, &[], b"\x00\x04\x00\x01\x04\x00");
        // xudp 开关不再决定命令 3 的准入，两种取值都必须解析为 Mux。
        for xudp in [false, true] {
            let mut wire = Wire::new(bytes.clone()).fragmented();
            assert!(matches!(
                handshake_with_xudp(&mut wire, &users(), xudp)
                    .await
                    .unwrap(),
                Accepted::Mux { user } if user == "alice"
            ));
            assert_eq!(wire.remaining(), b"\x00\x04\x00\x01\x04\x00");
        }
        let mut wrong = bytes;
        wrong[1] ^= 1;
        let mut wrong = Wire::new(wrong);
        assert_eq!(
            handshake_with_xudp(&mut wrong, &users(), true)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(wrong.closed && wrong.output.is_empty());
    }

    #[tokio::test]
    async fn user_selection_works_at_every_position() {
        let mut users = users();
        for _ in 0..users.len() {
            let mut io = Wire::new(request(1, &[0, 80, 1, 127, 0, 0, 1], b""));
            assert_eq!(
                handshake(&mut io, &users).await.unwrap().user.as_deref(),
                Some("alice")
            );
            users.rotate_left(1);
        }
    }

    #[tokio::test]
    async fn wrong_uuid_closes_without_response_or_credentials() {
        let valid = request(1, &[0, 80, 1, 127, 0, 0, 1], b"secret-payload");
        for index in 1..=16 {
            let mut bytes = valid.clone();
            bytes[index] ^= 1;
            let mut io = Wire::new(bytes);
            let error = handshake(&mut io, &users()).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(error.to_string(), "VLESS 认证失败");
            assert!(io.closed && io.output.is_empty());
        }
        for users in [
            vec![],
            vec![VlessUser {
                name: "invalid".into(),
                uuid: "non-uuid-secret".into(),
                flow: VlessFlow::Vision,
            }],
        ] {
            let mut bytes = valid.clone();
            bytes[1..17].fill(0);
            let mut io = Wire::new(bytes);
            let error = handshake(&mut io, &users).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(error.to_string(), "VLESS 认证失败");
            assert!(io.closed && io.output.is_empty());
        }
    }

    #[tokio::test]
    async fn rejects_versions_addons_and_unsupported_commands_without_success() {
        let valid = request(1, &[0, 80, 1, 127, 0, 0, 1], b"secret-payload");
        for (offset, rejected) in [
            (0, &[1, 255][..]),
            (17, &[1, 2, 255][..]),
            // 命令 3 能被解析为 Mux，但 `handshake` 的返回类型无法承载，仍失败关闭。
            (18, &[0, 3, 4, 255][..]),
        ] {
            for byte in rejected {
                let mut bytes = valid.clone();
                bytes[offset] = *byte;
                let mut io = Wire::new(bytes).fragmented();
                let error = handshake(&mut io, &users()).await.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(io.closed && io.output.is_empty());
                assert!(!error.to_string().contains("secret-payload"));
            }
        }
    }

    #[tokio::test]
    async fn invalid_address_types_and_domains_fail() {
        for atyp in [0, 4, 255] {
            let mut io = Wire::new(request(1, &[0, 80, atyp], b""));
            assert_eq!(
                handshake(&mut io, &users()).await.unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            assert!(io.closed && io.output.is_empty());
        }
        for domain in [
            &b""[..],
            b"bad domain",
            b"nul\0byte",
            b"new\nline",
            &[0xff],
            &[0x7f],
        ] {
            let mut target = vec![0, 80, 2, domain.len() as u8];
            target.extend_from_slice(domain);
            let mut io = Wire::new(request(1, &target, b""));
            assert_eq!(
                handshake(&mut io, &users()).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(io.closed && io.output.is_empty());
        }
    }

    #[tokio::test]
    async fn domain_and_port_boundaries_are_accepted() {
        for port in [0u16, 65535] {
            let mut target = port.to_be_bytes().to_vec();
            target.extend_from_slice(&[2, 255]);
            target.extend_from_slice(&[b'a'; 255]);
            let mut io = Wire::new(request(1, &target, b"payload")).fragmented();
            let parsed = handshake(&mut io, &users()).await.unwrap();
            assert_eq!(
                parsed.target,
                Target {
                    host: Host::Domain("a".repeat(255)),
                    port
                }
            );
            assert_eq!(io.remaining(), b"payload");
        }
    }

    #[tokio::test]
    async fn every_truncated_request_prefix_fails_and_closes() {
        for (target, _) in targets() {
            for command in [1, 2] {
                let bytes = request(command, &target, b"");
                for end in 0..bytes.len() {
                    let mut io = Wire::new(bytes[..end].to_vec()).fragmented();
                    assert_eq!(
                        handshake(&mut io, &users()).await.unwrap_err().kind(),
                        io::ErrorKind::UnexpectedEof
                    );
                    assert!(io.closed && io.output.is_empty());
                }
            }
        }
    }

    #[tokio::test]
    async fn udp_split_and_combined_frames_keep_boundaries_and_empty_frames() {
        let wire = b"\x00\x03one\x00\x00\x00\x03two";
        for fragmented in [false, true] {
            let mut io = Wire::new(wire.to_vec());
            if fragmented {
                io = io.fragmented();
            }
            assert_eq!(read_datagram(&mut io, 3).await.unwrap(), b"one");
            assert!(read_datagram(&mut io, 0).await.unwrap().is_empty());
            assert_eq!(read_datagram(&mut io, 3).await.unwrap(), b"two");
            assert!(io.remaining().is_empty());
        }
        assert_eq!(encode_datagram(b"one").unwrap(), b"\x00\x03one");
        assert_eq!(encode_datagram(b"").unwrap(), b"\x00\x00");
    }

    #[tokio::test]
    async fn udp_lengths_are_big_endian_payload_only_and_checked_before_payload() {
        for (length, prefix) in [
            (0, [0, 0]),
            (1, [0, 1]),
            (255, [0, 255]),
            (256, [1, 0]),
            (65535, [255, 255]),
        ] {
            let payload = vec![0x5a; length];
            let mut wire = prefix.to_vec();
            wire.extend_from_slice(&payload);
            assert_eq!(encode_datagram(&payload).unwrap(), wire);
            assert_eq!(
                read_datagram(&mut wire.as_slice(), length).await.unwrap(),
                payload
            );
            if length > 0 {
                let mut io = Wire::new(wire);
                assert_eq!(
                    read_datagram(&mut io, length - 1).await.unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
                assert_eq!(io.remaining(), payload);
                // 仅长度字段即可拒绝超限，不等待尚未到达的载荷。
                assert_eq!(
                    read_datagram(&mut prefix.as_slice(), length - 1)
                        .await
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidData
                );
            }
        }
        assert_eq!(
            encode_datagram(&vec![0; 65536]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn every_truncated_udp_frame_prefix_fails() {
        for frame in [&b"\x00\x00"[..], b"\x00\x03abc"] {
            for end in 0..frame.len() {
                let mut io = Wire::new(frame[..end].to_vec()).fragmented();
                assert_eq!(
                    read_datagram(&mut io, 65535).await.unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof
                );
            }
        }
    }
}
