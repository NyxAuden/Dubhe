use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::session::{Host, Target};

/// 读取一个 SOCKS 风格地址，仅读取地址字段，不预读后续载荷。
pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Target> {
    // 最大地址为类型、域名长度、255 字节域名和两字节端口。
    let mut bytes = [0u8; 259];
    bytes[0] = r.read_u8().await?;
    let (prefix, body) = match bytes[0] {
        1 => (1, 6),
        4 => (1, 18),
        3 => {
            bytes[1] = r.read_u8().await?;
            if bytes[1] == 0 {
                return Err(invalid_address());
            }
            (2, usize::from(bytes[1]) + 2)
        }
        _ => return Err(unsupported_address()),
    };
    r.read_exact(&mut bytes[prefix..prefix + body]).await?;
    decode(&bytes[..prefix + body]).map(|(target, _)| target)
}

pub fn encode(target: &Target) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(259);
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            bytes.push(4);
            bytes.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            if !valid_domain(domain.as_bytes()) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "无效目标域名"));
            }
            bytes.extend_from_slice(&[3, domain.len() as u8]);
            bytes.extend_from_slice(domain.as_bytes());
        }
    }
    bytes.extend_from_slice(&target.port.to_be_bytes());
    Ok(bytes)
}

// 流与数据报共用地址验证；返回实际消费长度，保留报文尾部。
pub(super) fn decode(bytes: &[u8]) -> io::Result<(Target, usize)> {
    let atyp = *bytes.first().ok_or_else(truncated_address)?;
    let (host, port_offset) = match atyp {
        1 => {
            let octets: [u8; 4] = take(bytes, 1, 4)?.try_into().unwrap();
            (Host::Ip(Ipv4Addr::from(octets).into()), 5)
        }
        4 => {
            let octets: [u8; 16] = take(bytes, 1, 16)?.try_into().unwrap();
            (Host::Ip(Ipv6Addr::from(octets).into()), 17)
        }
        3 => {
            let length = usize::from(*bytes.get(1).ok_or_else(truncated_address)?);
            let domain = take(bytes, 2, length)?;
            if !valid_domain(domain) {
                return Err(invalid_address());
            }
            let domain = std::str::from_utf8(domain).map_err(|_| invalid_address())?;
            (Host::Domain(domain.to_owned()), 2 + length)
        }
        _ => return Err(unsupported_address()),
    };
    let port = u16::from_be_bytes(take(bytes, port_offset, 2)?.try_into().unwrap());
    Ok((Target { host, port }, port_offset + 2))
}

fn take(bytes: &[u8], offset: usize, length: usize) -> io::Result<&[u8]> {
    bytes
        .get(offset..offset + length)
        .ok_or_else(truncated_address)
}

fn valid_domain(bytes: &[u8]) -> bool {
    // 线协议域名使用 ASCII（国际化域名应先编码为 A-label），拒绝空白与控制字符。
    !bytes.is_empty() && bytes.len() <= 255 && bytes.iter().all(u8::is_ascii_graphic)
}

fn invalid_address() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "无效目标地址")
}

fn unsupported_address() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "不支持的地址类型")
}

fn truncated_address() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "地址字段被截断")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::test_io::Wire;

    #[tokio::test]
    async fn independent_wire_addresses_and_fragmented_reads() {
        let mut ipv6 = vec![4];
        ipv6.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ipv6.extend_from_slice(&[0x01, 0xbb]);
        let cases = [
            (
                vec![1, 192, 0, 2, 7, 0x01, 0xbb],
                Host::Ip("192.0.2.7".parse().unwrap()),
            ),
            (ipv6, Host::Ip("2001:db8::1".parse().unwrap())),
            (
                b"\x03\x0bexample.org\x01\xbb".to_vec(),
                Host::Domain("example.org".into()),
            ),
        ];
        for (bytes, host) in cases {
            let target = Target { host, port: 443 };
            assert_eq!(encode(&target).unwrap(), bytes);
            for fragmented in [false, true] {
                let mut input = bytes.clone();
                input.extend_from_slice(b"payload");
                let mut io = Wire::new(input);
                if fragmented {
                    io = io.fragmented();
                }
                assert_eq!(read(&mut io).await.unwrap(), target);
                assert_eq!(io.remaining(), b"payload");
            }
            for end in 0..bytes.len() {
                assert_eq!(
                    read(&mut &bytes[..end]).await.unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof
                );
            }
        }
    }

    #[tokio::test]
    async fn address_boundaries_and_invalid_domains() {
        let domain = "a".repeat(255);
        let mut wire = vec![3, 255];
        wire.extend_from_slice(domain.as_bytes());
        wire.extend_from_slice(&[0, 0]);
        let target = Target {
            host: Host::Domain(domain),
            port: 0,
        };
        assert_eq!(read(&mut wire.as_slice()).await.unwrap(), target);
        assert_eq!(encode(&target).unwrap(), wire);
        for invalid in [
            "".to_owned(),
            "a".repeat(256),
            "a b".to_owned(),
            "a\0b".to_owned(),
            "例.test".to_owned(),
        ] {
            assert!(
                encode(&Target {
                    host: Host::Domain(invalid),
                    port: 80
                })
                .is_err()
            );
        }
        for bytes in [
            vec![3, 0, 0, 80],
            vec![3, 1, 0xff, 0, 80],
            vec![3, 1, 0, 0, 80],
        ] {
            assert_eq!(
                read(&mut bytes.as_slice()).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert_eq!(
            read(&mut &[2][..]).await.unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let zero = read(&mut &[1, 0, 0, 0, 0, 0, 0][..]).await.unwrap();
        assert_eq!(
            zero,
            "0.0.0.0:0".parse::<std::net::SocketAddr>().unwrap().into()
        );
    }
}
