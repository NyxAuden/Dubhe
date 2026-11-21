//! VLESS 命令3中的 UDP 帧；不接受 TCP 复用或跨承载续接。
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::session::{Host, Target};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    New,
    Keep,
    End,
    KeepAlive,
}

#[derive(Debug)]
pub struct Frame {
    pub id: u16,
    pub status: Status,
    pub target: Option<Target>,
    pub payload: Option<Vec<u8>>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// 固定栈缓冲读取元数据；长度与尾部必须精确匹配已支持的格式。
pub async fn read<R: AsyncRead + Unpin>(r: &mut R, max_payload: usize) -> io::Result<Frame> {
    let length = usize::from(r.read_u16().await?);
    read_frame(r, length, max_payload).await
}

/// 仅帧边界的干净承载 EOF 为会话结束；半长度、半帧仍保留错误。
pub(crate) async fn read_optional<R: AsyncRead + Unpin>(
    r: &mut R,
    max_payload: usize,
) -> io::Result<Option<Frame>> {
    let mut first = [0];
    if r.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let length = usize::from(u16::from_be_bytes([first[0], r.read_u8().await?]));
    read_frame(r, length, max_payload).await.map(Some)
}

async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    length: usize,
    max_payload: usize,
) -> io::Result<Frame> {
    if !(4..=512).contains(&length) {
        return Err(invalid("XUDP 元数据长度错误"));
    }
    let mut metadata = [0; 512];
    r.read_exact(&mut metadata[..length]).await?;
    let id = u16::from_be_bytes([metadata[0], metadata[1]]);
    let status = match metadata[2] {
        1 => Status::New,
        2 => Status::Keep,
        3 => Status::End,
        4 => Status::KeepAlive,
        _ => return Err(invalid("XUDP 状态错误")),
    };
    let options = metadata[3];
    // Error 只用于 End；End 的可选数据消费后丢弃，不作为 UDP 发送。
    if options & !3 != 0 || (options & 2 != 0 && status != Status::End) {
        return Err(invalid("XUDP 选项错误"));
    }
    let has_data = options & 1 != 0;
    let mut rest = &metadata[4..length];
    let target = if status == Status::New || (status == Status::Keep && !rest.is_empty()) {
        if rest.read_u8().await? != 2 {
            return Err(invalid("XUDP 仅支持 UDP 网络"));
        }
        Some(super::vless::read_target(&mut rest).await?)
    } else {
        None
    };
    // GlobalID 仅 New+Data 可携带；不保存为可跨连接复用的键。
    if !(rest.is_empty() || (status == Status::New && has_data && rest.len() == 8)) {
        return Err(invalid("XUDP 未支持的元数据尾部"));
    }
    let payload = if has_data {
        Some(super::vless::read_datagram(r, max_payload).await?)
    } else {
        None
    };
    Ok(Frame {
        id,
        status,
        target,
        payload,
    })
}

/// 回程携带 UDP 实际来源，不能发送 New 给现有 XUDP 客户端。
pub fn datagram(id: u16, target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0, 0];
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&[2, 1, 2]);
    bytes.extend_from_slice(&target.port.to_be_bytes());
    match &target.host {
        Host::Ip(std::net::IpAddr::V4(ip)) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        Host::Ip(std::net::IpAddr::V6(ip)) => {
            bytes.push(3);
            bytes.extend_from_slice(&ip.octets());
        }
        Host::Domain(domain) => {
            if domain.is_empty()
                || domain.len() > 255
                || !domain.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err(invalid("XUDP 域名错误"));
            }
            bytes.extend_from_slice(&[2, domain.len() as u8]);
            bytes.extend_from_slice(domain.as_bytes());
        }
    }
    let length = (bytes.len() - 2) as u16;
    bytes[..2].copy_from_slice(&length.to_be_bytes());
    let payload_length = u16::try_from(payload.len()).map_err(|_| invalid("XUDP 数据报过长"))?;
    bytes.extend_from_slice(&payload_length.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

pub fn end(id: u16, error: bool) -> [u8; 6] {
    let [high, low] = id.to_be_bytes();
    [0, 4, high, low, 3, if error { 2 } else { 0 }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::test_io::Wire;

    // 独立字节：会话0x1234，UDP 127.0.0.1:53，载荷abc。
    const NEW: &[u8] = b"\x00\x0c\x12\x34\x01\x01\x02\x00\x35\x01\x7f\x00\x00\x01\x00\x03abc";

    #[tokio::test]
    async fn split_combined_frames_and_response_bytes() {
        for fragmented in [false, true] {
            let mut bytes = NEW.to_vec();
            bytes.extend_from_slice(b"\x00\x04\x12\x34\x02\x01\x00\x03def");
            bytes.extend_from_slice(b"\x00\x04\x00\x00\x04\x00");
            bytes.extend_from_slice(b"\x00\x04\x12\x34\x03\x02");
            let mut r = Wire::new(bytes);
            if fragmented {
                r = r.fragmented();
            }
            let first = read(&mut r, 3).await.unwrap();
            assert_eq!(first.id, 0x1234);
            assert_eq!(first.status, Status::New);
            assert_eq!(
                first.target,
                Some(
                    "127.0.0.1:53"
                        .parse::<std::net::SocketAddr>()
                        .unwrap()
                        .into()
                )
            );
            assert_eq!(first.payload.as_deref(), Some(b"abc".as_slice()));
            let mut expected = NEW.to_vec();
            expected[4] = 2;
            assert_eq!(
                datagram(first.id, first.target.as_ref().unwrap(), b"abc").unwrap(),
                expected
            );
            let second = read(&mut r, 3).await.unwrap();
            assert_eq!(second.status, Status::Keep);
            assert!(second.target.is_none());
            assert_eq!(second.payload.unwrap(), b"def");
            assert_eq!(read(&mut r, 3).await.unwrap().status, Status::KeepAlive);
            assert_eq!(read(&mut r, 3).await.unwrap().status, Status::End);
            assert!(r.remaining().is_empty());
        }
        assert_eq!(end(0x1234, false), [0, 4, 0x12, 0x34, 3, 0]);
        assert_eq!(end(0x1234, true), [0, 4, 0x12, 0x34, 3, 2]);
    }

    #[tokio::test]
    async fn optional_frame_accepts_only_clean_boundary_eof_not_partial_lengths_or_frames() {
        assert!(read_optional(&mut &b""[..], 3).await.unwrap().is_none());
        for end in 1..NEW.len() {
            assert!(read_optional(&mut &NEW[..end], 3).await.is_err());
        }
        let mut input = NEW;
        let frame = read_optional(&mut input, 3).await.unwrap().unwrap();
        assert_eq!(frame.id, 0x1234);
        assert!(read_optional(&mut input, 3).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn global_id_and_targets_have_exact_lengths() {
        for extra in 0..=9 {
            let mut bytes = NEW[..14].to_vec();
            bytes[1] += extra;
            bytes.extend(vec![0x55; extra as usize]);
            bytes.extend_from_slice(&NEW[14..]);
            assert_eq!(
                read(&mut bytes.as_slice(), 3).await.is_ok(),
                extra == 0 || extra == 8
            );
        }
        for (wire, host) in [
            (b"\x00\x0d\x00\x01\x02\x01\x02\x01\xbb\x02\x04test\x00\x01x".as_slice(), Host::Domain("test".into())),
            (b"\x00\x18\x00\x01\x02\x01\x02\x01\xbb\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01x".as_slice(), Host::Ip("::1".parse().unwrap())),
        ] {
            let mut input = wire;
            let frame = read(&mut input, 1).await.unwrap();
            let target = Target { host, port: 443 };
            assert_eq!(frame.target, Some(target.clone()));
            assert_eq!(datagram(1, &target, b"x").unwrap(), wire);
        }
    }

    #[tokio::test]
    async fn malformed_metadata_and_payload_limits_fail() {
        for (offset, values) in [
            (4, &[0, 5, 255][..]),
            (5, &[2, 3, 4, 255]),
            (6, &[0, 1, 3]),
            (9, &[0, 4, 255]),
        ] {
            for value in values {
                let mut bytes = NEW.to_vec();
                bytes[offset] = *value;
                assert!(read(&mut bytes.as_slice(), 3).await.is_err());
            }
        }
        for len in [0u16, 3, 513, 65535] {
            assert!(read(&mut len.to_be_bytes().as_slice(), 3).await.is_err());
        }
        // 只给出长度即可拒绝，不等待载荷。
        assert_eq!(
            read(&mut &NEW[..16], 2).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        for bytes in [
            b"\x00\x05\x00\x00\x04\x00\x00".as_slice(),
            b"\x00\x04\x00\x00\x01\x00",
        ] {
            let mut input = bytes;
            assert!(read(&mut input, 3).await.is_err());
        }
    }

    #[tokio::test]
    async fn every_truncated_prefix_fails() {
        for end in 0..NEW.len() {
            assert!(
                read(&mut Wire::new(&NEW[..end]).fragmented(), 3)
                    .await
                    .is_err()
            );
        }
        let frame = read(&mut &b"\x00\x04\x00\x00\x02\x01\x00\x00"[..], 0)
            .await
            .unwrap();
        assert_eq!(frame.payload, Some(vec![]));
    }
}
