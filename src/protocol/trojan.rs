use std::io;

use sha2::{Digest, Sha224};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    config::User,
    session::{Command, Request, Target},
};

use super::address;

/// TLS 由运行时完成；此处只读取 Trojan 头，失败时关闭写方向且不发送应答。
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    users: &[User],
) -> io::Result<Request> {
    let result = read_request(io, users).await;
    if result.is_err() {
        // 调用方随后丢弃流，确保读方向和相关任务也被回收。
        let _ = io.shutdown().await;
    }
    result
}

// 可关闭整个承载的入口在认证失败后直接丢弃流，不在无人继续读时等待 WS Close。
// 普通 TLS 仍经 handshake 保留原有 shutdown 行为。
pub(crate) async fn read_request<R: AsyncRead + Unpin>(
    io: &mut R,
    users: &[User],
) -> io::Result<Request> {
    let mut supplied = [0; 56];
    io.read_exact(&mut supplied).await?;
    let lowercase_hex = supplied
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte));
    let mut accepted = Choice::from(0);
    let mut selected = 0u64;
    // 每个用户均计算完整摘要并比较全部 56 字节，身份选择也不提前分支返回。
    for (index, user) in users.iter().enumerate() {
        let expected = password_digest(&user.password);
        let matches = supplied.ct_eq(&expected);
        selected = u64::conditional_select(&selected, &(index as u64), matches & !accepted);
        accepted |= matches;
    }
    if !lowercase_hex || !bool::from(accepted) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Trojan 认证失败",
        ));
    }
    read_crlf(io).await?;
    let command = match io.read_u8().await? {
        1 => Command::Connect,
        3 => Command::UdpAssociate,
        _ => return Err(invalid("不支持的 Trojan 命令")),
    };
    let target = address::read(io).await?;
    read_crlf(io).await?;
    Ok(Request {
        command,
        target,
        user: Some(users[selected as usize].name.clone()),
    })
}

fn password_digest(password: &str) -> [u8; 56] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha224::digest(password.as_bytes());
    let mut encoded = [0; 56];
    for (index, byte) in digest.iter().enumerate() {
        encoded[2 * index] = HEX[usize::from(byte >> 4)];
        encoded[2 * index + 1] = HEX[usize::from(byte & 0x0f)];
    }
    encoded
}

/// 读取完整单帧；分配载荷前检查上限，所有等待由调用方的期限约束。
pub async fn read_datagram<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> io::Result<(Target, Vec<u8>)> {
    let target = address::read(r).await?;
    let length = usize::from(r.read_u16().await?);
    if length > max {
        return Err(invalid("Trojan 数据报超过长度上限"));
    }
    read_crlf(r).await?;
    let mut payload = vec![0; length];
    r.read_exact(&mut payload).await?;
    Ok((target, payload))
}

pub fn encode_datagram(target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Trojan 数据报超过线协议长度上限",
        )
    })?;
    let mut bytes = address::encode(target)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

async fn read_crlf<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<()> {
    let mut separator = [0; 2];
    r.read_exact(&mut separator).await?;
    if separator != *b"\r\n" {
        return Err(invalid("无效 Trojan 分隔符"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{protocol::test_io::Wire, session::Host};

    // SHA-224("abc") 的公开测试向量；不使用服务端摘要或编码函数构造请求。
    const DIGEST: &[u8] = b"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";

    fn users() -> Vec<User> {
        vec![
            User {
                name: "first".into(),
                password: "other".into(),
            },
            User {
                name: "alice".into(),
                password: "abc".into(),
            },
            User {
                name: "last".into(),
                password: "another".into(),
            },
        ]
    }

    fn request(command: u8, address: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut wire = DIGEST.to_vec();
        wire.extend_from_slice(b"\r\n");
        wire.push(command);
        wire.extend_from_slice(address);
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(payload);
        wire
    }

    #[tokio::test]
    async fn split_and_combined_requests_preserve_payload_for_every_address_type() {
        for (address, host) in [
            (
                vec![1, 192, 0, 2, 9, 1, 187],
                Host::Ip("192.0.2.9".parse().unwrap()),
            ),
            (
                vec![4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187],
                Host::Ip("::1".parse().unwrap()),
            ),
            (
                b"\x03\x0bexample.org\x01\xbb".to_vec(),
                Host::Domain("example.org".into()),
            ),
        ] {
            for (command, expected) in [(1, Command::Connect), (3, Command::UdpAssociate)] {
                for fragmented in [false, true] {
                    let mut io = Wire::new(request(command, &address, b"\0payload\r\n"));
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
    async fn invalid_authentication_closes_without_echoing_data() {
        let valid = request(1, &[1, 127, 0, 0, 1, 0, 80], b"sensitive-payload");
        // 首字节、末字节、大小写和非十六进制字节均失败。
        for (index, byte) in [(0, b'0'), (55, b'0'), (5, b'D'), (3, b'g'), (3, 0xff)] {
            let mut bytes = valid.clone();
            bytes[index] = byte;
            let mut io = Wire::new(bytes);
            let error = handshake(&mut io, &users()).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(error.to_string(), "Trojan 认证失败");
            assert!(io.closed);
            assert!(io.output.is_empty());
        }
        let mut io = Wire::new(valid);
        assert_eq!(
            handshake(&mut io, &[]).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(io.closed);
    }

    #[tokio::test]
    async fn rejects_bad_separators_commands_and_address_types() {
        let valid = request(1, &[1, 127, 0, 0, 1, 0, 80], b"");
        for index in [56, 57, valid.len() - 2, valid.len() - 1] {
            let mut bytes = valid.clone();
            bytes[index] = 0;
            let mut io = Wire::new(bytes);
            assert_eq!(
                handshake(&mut io, &users()).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(io.closed && io.output.is_empty());
        }
        for command in [0, 2, 0xff] {
            let mut io = Wire::new(request(command, &[1, 127, 0, 0, 1, 0, 80], b""));
            assert!(handshake(&mut io, &users()).await.is_err());
            assert!(io.closed && io.output.is_empty());
        }
        let mut io = Wire::new(request(1, &[0xff], b""));
        assert!(handshake(&mut io, &users()).await.is_err());
        assert!(io.closed && io.output.is_empty());
    }

    #[tokio::test]
    async fn every_truncated_request_prefix_fails_and_closes() {
        let bytes = request(1, b"\x03\x0bexample.org\x00\x50", b"");
        for end in 0..bytes.len() {
            let mut io = Wire::new(bytes[..end].to_vec()).fragmented();
            assert_eq!(
                handshake(&mut io, &users()).await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert!(io.closed && io.output.is_empty());
        }
    }

    #[tokio::test]
    async fn multiple_frames_fragmented_or_combined_preserve_boundaries() {
        let first = b"\x01\xc0\x00\x02\x07\x00\x35\x00\x03\r\none";
        let second = b"\x03\x0bexample.org\x01\xbb\x00\x00\r\n";
        let third = [
            4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53, 0, 3, 13, 10, b't', b'w',
            b'o',
        ];
        let mut bytes = first.to_vec();
        bytes.extend_from_slice(second);
        bytes.extend_from_slice(&third);
        for fragmented in [false, true] {
            let mut io = Wire::new(bytes.clone());
            if fragmented {
                io = io.fragmented();
            }
            let (one, payload) = read_datagram(&mut io, 3).await.unwrap();
            assert_eq!(
                one,
                "192.0.2.7:53"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into()
            );
            assert_eq!(payload, b"one");
            assert_eq!(encode_datagram(&one, &payload).unwrap(), first);
            let (two, payload) = read_datagram(&mut io, 0).await.unwrap();
            assert_eq!(
                two,
                Target {
                    host: Host::Domain("example.org".into()),
                    port: 443
                }
            );
            assert!(payload.is_empty());
            assert_eq!(encode_datagram(&two, &payload).unwrap(), second);
            let (three, payload) = read_datagram(&mut io, 3).await.unwrap();
            assert_eq!(
                three,
                "[::1]:53".parse::<std::net::SocketAddr>().unwrap().into()
            );
            assert_eq!(payload, b"two");
            assert_eq!(encode_datagram(&three, &payload).unwrap(), third);
            assert!(io.remaining().is_empty());
        }
    }

    #[tokio::test]
    async fn frame_lengths_are_big_endian_payload_only_and_bounded() {
        let address = [1, 127, 0, 0, 1, 0, 53];
        let target = "127.0.0.1:53"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into();
        for length in [0usize, 1, 256, 65535] {
            let payload = vec![0x5a; length];
            let mut wire = address.to_vec();
            wire.extend_from_slice(&(length as u16).to_be_bytes());
            wire.extend_from_slice(b"\r\n");
            wire.extend_from_slice(&payload);
            assert_eq!(encode_datagram(&target, &payload).unwrap(), wire);
            assert_eq!(
                read_datagram(&mut wire.as_slice(), length).await.unwrap(),
                (target.clone(), payload)
            );
            if length > 0 {
                let mut io = Wire::new(wire);
                assert_eq!(
                    read_datagram(&mut io, length - 1).await.unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
                assert_eq!(io.remaining().len(), length + 2);
            }
        }
        assert_eq!(
            encode_datagram(&target, &vec![0; 65536])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn truncated_frames_invalid_addresses_and_crlf_fail() {
        let frame = b"\x01\x7f\x00\x00\x01\x00\x35\x00\x03\r\nabc";
        for end in 0..frame.len() {
            assert_eq!(
                read_datagram(&mut &frame[..end], 65535)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        for index in [9, 10] {
            let mut bytes = frame.to_vec();
            bytes[index] = 0;
            assert_eq!(
                read_datagram(&mut bytes.as_slice(), 65535)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert!(read_datagram(&mut &[7][..], 65535).await.is_err());
    }
}
