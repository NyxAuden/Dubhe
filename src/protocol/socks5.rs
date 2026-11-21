use std::{io, net::SocketAddr};

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    config::User,
    session::{Command, Request, Target},
};

use super::address;

/// 只负责协商、认证和请求头；成功应答由运行时在资源准备成功后发送。
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    users: &[User],
) -> io::Result<Request> {
    let version = io.read_u8().await?;
    if version != 5 {
        return Err(invalid("无效 SOCKS5 版本"));
    }
    let count = usize::from(io.read_u8().await?);
    let mut methods = vec![0; count];
    io.read_exact(&mut methods).await?;
    let method = if users.is_empty() { 0 } else { 2 };
    if !methods.contains(&method) {
        io.write_all(&[5, 0xff]).await?;
        io.flush().await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "无可接受认证方法",
        ));
    }
    io.write_all(&[5, method]).await?;
    io.flush().await?;
    let user = if method == 2 {
        Some(authenticate(io, users).await?)
    } else {
        None
    };

    let mut header = [0; 3];
    io.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 {
        reply(io, 1, unspecified()).await?;
        return Err(invalid("无效 SOCKS5 请求头"));
    }
    let command = match header[1] {
        1 => Command::Connect,
        2 => Command::Bind,
        3 => Command::UdpAssociate,
        _ => {
            reply(io, 7, unspecified()).await?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "不支持的 SOCKS5 命令",
            ));
        }
    };
    let target = match address::read(io).await {
        Ok(target) => target,
        Err(error) => {
            let status = if error.kind() == io::ErrorKind::Unsupported {
                8
            } else {
                1
            };
            reply(io, status, unspecified()).await?;
            return Err(error);
        }
    };
    // UDP ASSOCIATE 中的全零地址或端口表示客户端尚未提供端点。
    Ok(Request {
        command,
        target,
        user,
    })
}

async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    users: &[User],
) -> io::Result<String> {
    let version = io.read_u8().await?;
    let name_len = usize::from(io.read_u8().await?);
    if version != 1 || name_len == 0 {
        return authentication_failed(io).await;
    }
    let mut name = vec![0; name_len];
    io.read_exact(&mut name).await?;
    let password_len = usize::from(io.read_u8().await?);
    if password_len == 0 {
        return authentication_failed(io).await;
    }
    let mut password = vec![0; password_len];
    io.read_exact(&mut password).await?;
    let mut identity = None;
    for user in users {
        let matches = name.as_slice().ct_eq(user.name.as_bytes())
            & password.as_slice().ct_eq(user.password.as_bytes());
        if bool::from(matches) {
            identity = Some(user.name.clone());
        }
    }
    match identity {
        Some(identity) => {
            io.write_all(&[1, 0]).await?;
            io.flush().await?;
            Ok(identity)
        }
        None => authentication_failed(io).await,
    }
}

async fn authentication_failed<S: AsyncWrite + Unpin>(io: &mut S) -> io::Result<String> {
    io.write_all(&[1, 1]).await?;
    io.flush().await?;
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "SOCKS5 认证失败",
    ))
}

pub async fn reply<W: AsyncWrite + Unpin>(
    w: &mut W,
    status: u8,
    bound: SocketAddr,
) -> io::Result<()> {
    let mut bytes = vec![5, status, 0];
    bytes.extend_from_slice(&address::encode(&bound.into())?);
    w.write_all(&bytes).await?;
    w.flush().await
}

pub fn decode_datagram(bytes: &[u8]) -> io::Result<(Target, Vec<u8>)> {
    let header = bytes
        .get(..3)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "SOCKS5 数据报头被截断"))?;
    if header != [0, 0, 0] {
        return Err(invalid("无效 SOCKS5 数据报保留位或分片字段"));
    }
    let (target, used) = address::decode(&bytes[3..])?;
    Ok((target, bytes[3 + used..].to_vec()))
}

pub fn encode_datagram(target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0, 0, 0];
    bytes.extend_from_slice(&address::encode(target)?);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn unspecified() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 0))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{protocol::test_io::Wire, session::Host};

    fn users() -> Vec<User> {
        vec![
            User {
                name: "other".into(),
                password: "other-secret".into(),
            },
            User {
                name: "alice".into(),
                password: "secret".into(),
            },
        ]
    }

    #[tokio::test]
    async fn connect_preserves_payload_with_fragmented_and_combined_headers() {
        let wire = b"\x05\x01\x00\x05\x01\x00\x03\x0bexample.org\x01\xbbpayload";
        for fragmented in [false, true] {
            let mut io = Wire::new(wire.to_vec());
            if fragmented {
                io = io.fragmented();
            }
            let request = handshake(&mut io, &[]).await.unwrap();
            assert_eq!(request.command, Command::Connect);
            assert_eq!(
                request.target,
                Target {
                    host: Host::Domain("example.org".into()),
                    port: 443
                }
            );
            assert_eq!(request.user, None);
            assert_eq!(io.output, [5, 0]);
            assert_eq!(io.remaining(), b"payload");
        }
    }

    #[tokio::test]
    async fn username_password_authentication_and_udp_unspecified_endpoint() {
        let mut io = Wire::new(
            b"\x05\x02\x00\x02\x01\x05alice\x06secret\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"
                .to_vec(),
        )
        .fragmented();
        let request = handshake(&mut io, &users()).await.unwrap();
        assert_eq!(request.command, Command::UdpAssociate);
        assert_eq!(request.user.as_deref(), Some("alice"));
        assert_eq!(request.target, unspecified().into());
        assert_eq!(io.output, [5, 2, 1, 0]);
    }

    #[tokio::test]
    async fn ipv4_and_ipv6_requests() {
        for (address, expected) in [
            (vec![1, 192, 0, 2, 9, 0, 53], "192.0.2.9:53"),
            (
                vec![4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53],
                "[::1]:53",
            ),
        ] {
            for command in [1, 3] {
                let mut bytes = vec![5, 1, 0, 5, command, 0];
                bytes.extend_from_slice(&address);
                let mut io = Wire::new(bytes).fragmented();
                assert_eq!(
                    handshake(&mut io, &[]).await.unwrap().target,
                    expected.parse::<SocketAddr>().unwrap().into()
                );
            }
        }
    }

    #[tokio::test]
    async fn rejects_authentication_downgrades_and_bad_credentials() {
        for bytes in [vec![5, 1, 0], vec![5, 0], vec![5, 1, 1]] {
            let mut io = Wire::new(bytes);
            assert_eq!(
                handshake(&mut io, &users()).await.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(io.output, [5, 0xff]);
        }
        let mut io = Wire::new(vec![5, 1, 2]);
        assert!(handshake(&mut io, &[]).await.is_err());
        assert_eq!(io.output, [5, 0xff]);
        for auth in [
            b"\x01\x05alice\x05wrong".as_slice(),
            b"\x01\x05nobod\x06secret".as_slice(),
            b"\x02\x05".as_slice(),
            b"\x01\x00".as_slice(),
            b"\x01\x05alice\x00".as_slice(),
        ] {
            let mut bytes = vec![5, 1, 2];
            bytes.extend_from_slice(auth);
            let mut io = Wire::new(bytes).fragmented();
            let error = handshake(&mut io, &users()).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(io.output, [5, 2, 1, 1]);
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[tokio::test]
    async fn rejects_unknown_command_atyp_and_reserved_byte() {
        for (request, expected_status) in [
            (vec![5, 0xff, 0], 7),
            (vec![5, 1, 0, 0xff], 8),
            (vec![5, 1, 1], 1),
            (vec![4, 1, 0], 1),
        ] {
            let mut bytes = vec![5, 1, 0];
            bytes.extend_from_slice(&request);
            let mut io = Wire::new(bytes);
            assert!(handshake(&mut io, &[]).await.is_err());
            assert_eq!(
                io.output,
                [5, 0, 5, expected_status, 0, 1, 0, 0, 0, 0, 0, 0]
            );
        }
    }

    #[tokio::test]
    async fn bind_command_parses_with_expected_peer() {
        let mut bytes = vec![5, 1, 0];
        bytes.extend_from_slice(&[5, 2, 0, 1, 127, 0, 0, 1, 0, 21]);
        let mut io = Wire::new(bytes);
        let request = handshake(&mut io, &[]).await.unwrap();
        assert_eq!(request.command, Command::Bind);
        assert_eq!(
            request.target.host,
            crate::session::Host::Ip("127.0.0.1".parse().unwrap())
        );
        assert_eq!(request.target.port, 21);
    }

    #[tokio::test]
    async fn all_truncated_handshake_prefixes_fail() {
        for (wire, configured) in [
            (
                b"\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50".as_slice(),
                vec![],
            ),
            (
                b"\x05\x01\x02\x01\x05alice\x06secret\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50"
                    .as_slice(),
                users(),
            ),
        ] {
            for end in 0..wire.len() {
                let mut io = Wire::new(wire[..end].to_vec());
                assert_eq!(
                    handshake(&mut io, &configured).await.unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof
                );
            }
        }
    }

    #[tokio::test]
    async fn reply_uses_bound_address_and_status() {
        let mut io = Wire::new(vec![]);
        reply(&mut io, 5, "192.0.2.8:1234".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(io.output, [5, 5, 0, 1, 192, 0, 2, 8, 4, 210]);
        io.output.clear();
        reply(&mut io, 0, "[::1]:443".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            io.output,
            [
                5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187
            ]
        );
    }

    #[test]
    fn datagrams_preserve_addresses_and_payload_boundaries() {
        let cases = [
            (
                vec![1, 192, 0, 2, 7, 0, 53],
                Host::Ip("192.0.2.7".parse().unwrap()),
            ),
            (
                vec![4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53],
                Host::Ip("::1".parse().unwrap()),
            ),
            (
                b"\x03\x0bexample.org\x00\x35".to_vec(),
                Host::Domain("example.org".into()),
            ),
        ];
        for (address, host) in cases {
            let target = Target { host, port: 53 };
            for payload in [b"".as_slice(), b"\0\xffdata".as_slice()] {
                let mut wire = vec![0, 0, 0];
                wire.extend_from_slice(&address);
                wire.extend_from_slice(payload);
                assert_eq!(
                    decode_datagram(&wire).unwrap(),
                    (target.clone(), payload.to_vec())
                );
                assert_eq!(encode_datagram(&target, payload).unwrap(), wire);
            }
        }
    }

    #[test]
    fn rejects_frag_reserved_bits_and_truncated_datagrams() {
        let valid = [0, 0, 0, 1, 127, 0, 0, 1, 0, 53];
        for end in 0..valid.len() {
            assert!(decode_datagram(&valid[..end]).is_err());
        }
        for index in 0..3 {
            let mut wire = valid;
            wire[index] = 1;
            assert_eq!(
                decode_datagram(&wire).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert!(decode_datagram(&[0, 0, 0, 7]).is_err());
        assert_eq!(decode_datagram(&valid).unwrap().1, b"");
    }
}
