//! 多处协议实现共用的纯函数。
//!
//! 只放「语义固定、与协议无关、复制会漂移」的小工具；带协议状态的逻辑留在
//! 各自模块里。

/// FNV-1a 32 位哈希。
///
/// VMess 头部校验与 KCP 掩码都依赖这组常量；三处实现曾完全重复，收敛在此
/// 以免改常量时只改到其中一处。
pub(crate) fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn fnv1a_matches_known_vectors() {
        assert_eq!(super::fnv1a(b""), 0x811c_9dc5);
        assert_eq!(super::fnv1a(b"a"), 0xe40c292c);
        assert_eq!(super::fnv1a(b"foobar"), 0xbf9cf968);
    }
}

/// 单个十六进制字符转数值；大小写等价。
pub(crate) fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// 在缓冲区内查找 `\r\n\r\n`，返回结束位置（含分隔符）。
pub(crate) fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

/// 有界读取 HTTP/1.x 请求头，返回 `(缓冲区, 头部结束位置)`。
///
/// `label` 只用于错误文案，让不同入口的日志能区分来源。
pub(crate) async fn read_http_head<S>(
    io: &mut S,
    max_head: usize,
    read_chunk: usize,
    label: &str,
) -> std::io::Result<(Vec<u8>, usize)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt as _;
    let mut buffer = Vec::with_capacity(read_chunk);
    loop {
        if let Some(end) = find_head_end(&buffer) {
            return Ok((buffer, end));
        }
        if buffer.len() >= max_head {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{label}请求头超长"),
            ));
        }
        let mut chunk = vec![0u8; read_chunk];
        let remaining = (max_head - buffer.len()).min(chunk.len());
        let read = io.read(&mut chunk[..remaining]).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("{label}请求头提前结束"),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(test)]
mod head_tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    #[tokio::test]
    async fn read_http_head_returns_buffer_and_boundary() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\ntail")
                .await
                .unwrap();
        });
        let (buffer, end) = read_http_head(&mut server, 8192, 1024, "测试")
            .await
            .unwrap();
        assert_eq!(&buffer[..end], b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        assert_eq!(&buffer[end..], b"tail");
    }

    #[tokio::test]
    async fn read_http_head_rejects_oversized_and_truncated() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
            drop(client);
        });
        let error = read_http_head(&mut server, 8192, 1024, "测试")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);

        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = client.write_all(&[b'a'; 64]).await;
            std::future::pending::<()>().await;
        });
        let error = read_http_head(&mut server, 8, 16, "测试")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
