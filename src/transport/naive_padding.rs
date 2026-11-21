//! NaiveProxy padding 扩展：能力头与首 8 个数据块的 PaddedData 帧。
//!
//! 规范要求客户端在 CONNECT 请求中带 `padding` 头；服务端支持时在 200
//! 响应中回 `Padding` 头，并把隧道双向的前 8 个数据块编码为：
//! 2 字节原始长度（大端）、1 字节 padding 长度、原始数据、零填充。
//! 不做能力协商时保持普通字节流，普通浏览器客户端不受影响。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 双向各自参与 PaddedData 的数据块数量。
const PAD_BLOCKS: u8 = 8;
/// PaddedData 原始数据上限。
const MAX_ORIGINAL: usize = 65_535;
/// 请求 `padding` 头长度范围（naiveproxy README：
/// 请求 [16,32]，响应 [30,62]）。
const MIN_REQUEST_PADDING: usize = 16;
const MAX_REQUEST_PADDING: usize = 32;
/// 响应 `Padding` 头长度范围。
const MIN_HEADER_PADDING: usize = 30;
const MAX_HEADER_PADDING: usize = 61;
/// 规范指定的首 16 字节非 Huffman 字符集。
const HEADER_PREFIX: &[u8] = b"!#$()+<>?@[]^`{}";

/// 生成规范长度区间的 `Padding` 头值。
///
/// 请求与响应的长度区间不同：请求 [16,32]，响应 [30,62)。用错区间不会影响
/// 互通（对端只检查存在与非空），但请求 HEADERS 帧会比官方客户端长
/// 15–30 字节，正是该 padding 想抹平的长度指纹。
fn header_value_range(min: usize, max: usize) -> io::Result<Vec<u8>> {
    let mut random = [0u8; 9];
    aws_lc_rs::rand::fill(&mut random).map_err(|_| io::Error::other("Naive padding 随机源失败"))?;
    let length = min + usize::from(random[0]) % (max - min + 1);
    let mut value = vec![b'~'; length];
    // 固定 forwardproxy：前16字节取64位随机数的16个四位值，后缀全为 '~'。
    for (index, byte) in value[..16].iter_mut().enumerate() {
        let bits = random[1 + index / 2] >> ((index % 2) * 4);
        *byte = HEADER_PREFIX[usize::from(bits & 15)];
    }
    Ok(value)
}

/// 客户端 CONNECT 请求的 `padding` 头值，16..=32 字节。
pub(crate) fn request_header_value() -> io::Result<Vec<u8>> {
    header_value_range(MIN_REQUEST_PADDING, MAX_REQUEST_PADDING)
}

/// 服务端 CONNECT 响应的 `padding` 头值，30..=61 字节。
pub(crate) fn header_value() -> io::Result<Vec<u8>> {
    header_value_range(MIN_HEADER_PADDING, MAX_HEADER_PADDING)
}

/// 包装隧道的双向 PaddedData 编解码器。
pub(crate) struct PaddedStream<S> {
    inner: S,
    enabled: bool,
    read_frames: u8,
    read_stash: Vec<u8>,
    read_out: Vec<u8>,
    read_out_pos: usize,
    write_frames: u8,
    write_pending: Vec<u8>,
    write_pending_pos: usize,
    write_closed: bool,
    failure: Option<io::ErrorKind>,
}

impl<S> PaddedStream<S> {
    pub(crate) fn new(inner: S, enabled: bool) -> Self {
        Self {
            inner,
            enabled,
            read_frames: 0,
            read_stash: Vec::new(),
            read_out: Vec::new(),
            read_out_pos: 0,
            write_frames: 0,
            write_pending: Vec::new(),
            write_pending_pos: 0,
            write_closed: false,
            failure: None,
        }
    }
}

impl<S: AsyncRead + Unpin> PaddedStream<S> {
    fn receive(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.read_out_pos < self.read_out.len() {
                let available = &self.read_out[self.read_out_pos..];
                let count = available.len().min(buffer.remaining());
                buffer.put_slice(&available[..count]);
                self.read_out_pos += count;
                if self.read_out_pos == self.read_out.len() {
                    self.read_out.clear();
                    self.read_out_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if !self.enabled || self.read_frames >= PAD_BLOCKS {
                if !self.read_stash.is_empty() {
                    let count = self.read_stash.len().min(buffer.remaining());
                    buffer.put_slice(&self.read_stash[..count]);
                    self.read_stash.drain(..count);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut self.inner).poll_read(cx, buffer);
            }
            // 先尝试从 stash 解出完整 PaddedData。
            if self.read_stash.len() >= 3 {
                let original =
                    usize::from(u16::from_be_bytes([self.read_stash[0], self.read_stash[1]]));
                let padding = usize::from(self.read_stash[2]);
                let total = 3 + original + padding;
                if total > 3 + MAX_ORIGINAL + 255 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Naive padding 帧长度无效",
                    )));
                }
                if self.read_stash.len() >= total {
                    let payload = self.read_stash[3..3 + original].to_vec();
                    self.read_out.extend_from_slice(&payload);
                    self.read_stash.drain(..total);
                    self.read_frames += 1;
                    continue;
                }
            }
            let mut chunk = [0u8; 8192];
            let mut read_buffer = ReadBuf::new(&mut chunk);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let count = read_buffer.filled().len();
                    if count == 0 {
                        if self.read_stash.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Naive padding 帧被截断",
                        )));
                    }
                    self.read_stash.extend_from_slice(&chunk[..count]);
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for PaddedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(kind) = self.failure {
            return Poll::Ready(Err(io::Error::new(kind, "Naive padding流已失败")));
        }
        // 先写后读也推动已接受的有界块；背压不能阻止独立反向读取。
        if let Poll::Ready(Err(error)) = self.as_mut().poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        let result = self.as_mut().receive(cx, output);
        if let Poll::Ready(Err(error)) = &result {
            self.failure = Some(error.kind());
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> PaddedStream<S> {
    fn poll_drain(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(kind) = self.failure {
            return Poll::Ready(Err(io::Error::new(kind, "Naive padding流已失败")));
        }
        while self.write_pending_pos < self.write_pending.len() {
            let this = self.as_mut().get_mut();
            match Pin::new(&mut this.inner)
                .poll_write(cx, &this.write_pending[this.write_pending_pos..])
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    this.failure = Some(error.kind());
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(0)) => {
                    this.failure = Some(io::ErrorKind::WriteZero);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Naive padding 写入零字节",
                    )));
                }
                Poll::Ready(Ok(written)) => this.write_pending_pos += written,
            }
        }
        self.write_pending.clear();
        self.write_pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PaddedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 先排空前一次已经返回 Ok(n) 的帧；Pending 时绝不接受本次的新缓冲。
        std::task::ready!(self.as_mut().poll_drain(cx))?;
        if self.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !self.enabled || self.write_frames >= PAD_BLOCKS {
            let result = Pin::new(&mut self.inner).poll_write(cx, buffer);
            if let Poll::Ready(Err(error)) = &result {
                self.failure = Some(error.kind());
            }
            return result;
        }
        let original = buffer.len().min(MAX_ORIGINAL);
        let mut pad = [0u8; 1];
        if aws_lc_rs::rand::fill(&mut pad).is_err() {
            return Poll::Ready(Err(io::Error::other("Naive padding 随机源失败")));
        }
        self.write_pending
            .extend_from_slice(&(original as u16).to_be_bytes());
        self.write_pending.push(pad[0]);
        self.write_pending.extend_from_slice(&buffer[..original]);
        self.write_pending
            .resize(3 + original + usize::from(pad[0]), 0);
        self.write_frames += 1;
        // 缓冲接受即返回长度，后续 flush/write/shutdown 才排空；取消不会造成
        // 已发出的旧帧在下一次不同 write 中虚报成新缓冲的字节数。
        Poll::Ready(Ok(original))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_drain(cx))?;
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if let Poll::Ready(Err(error)) = &result {
            self.failure = Some(error.kind());
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        self.write_closed = true;
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        if let Poll::Ready(Err(error)) = &result {
            self.failure = Some(error.kind());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn response_header_matches_fixed_forwardproxy() {
        for _ in 0..256 {
            let header = header_value().unwrap();
            assert!((30..=61).contains(&header.len()));
            assert!(
                header[..16]
                    .iter()
                    .all(|byte| b"!#$()+<>?@[]^`{}".contains(byte))
            );
            assert!(header[16..].iter().all(|byte| *byte == b'~'));
        }
    }

    #[test]
    fn request_header_matches_spec_length_range() {
        // naiveproxy README：请求 [16,32]，响应 [30,62)。两者不可共用区间。
        for _ in 0..256 {
            let header = request_header_value().unwrap();
            assert!(
                (16..=32).contains(&header.len()),
                "请求 padding 头长度越界: {}",
                header.len()
            );
            assert!(
                header[..16]
                    .iter()
                    .all(|byte| b"!#$()+<>?@[]^`{}".contains(byte))
            );
        }
    }

    fn decode_written(bytes: &[u8], frames: usize) -> (Vec<Vec<u8>>, Vec<u8>) {
        let mut offset = 0;
        let mut payloads = Vec::new();
        for _ in 0..frames {
            let length = usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
            let padding = usize::from(bytes[offset + 2]);
            payloads.push(bytes[offset + 3..offset + 3 + length].to_vec());
            assert!(
                bytes[offset + 3 + length..offset + 3 + length + padding]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            offset += 3 + length + padding;
        }
        (payloads, bytes[offset..].to_vec())
    }
    struct ShortWriter {
        out: Arc<Mutex<Vec<u8>>>,
        blocked: Arc<AtomicBool>,
    }
    impl AsyncWrite for ShortWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.blocked.load(Ordering::SeqCst) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let count = data.len().min(2);
            self.out.lock().unwrap().extend_from_slice(&data[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn short_writes_cancelled_next_write_and_flush_do_not_duplicate_bytes() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let blocked = Arc::new(AtomicBool::new(true));
        let mut stream = PaddedStream::new(
            ShortWriter {
                out: bytes.clone(),
                blocked: blocked.clone(),
            },
            true,
        );
        assert_eq!(stream.write(b"first").await.unwrap(), 5);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                stream.write(b"cancelled")
            )
            .await
            .is_err()
        );
        blocked.store(false, Ordering::SeqCst);
        stream.flush().await.unwrap();
        assert_eq!(stream.write(b"second").await.unwrap(), 6);
        stream.flush().await.unwrap();
        let (payloads, rest) = decode_written(&bytes.lock().unwrap(), 2);
        assert_eq!(payloads, vec![b"first".to_vec(), b"second".to_vec()]);
        assert!(rest.is_empty());
    }
    #[tokio::test]
    async fn only_first_eight_writes_are_framed() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let blocked = Arc::new(AtomicBool::new(false));
        let mut stream = PaddedStream::new(
            ShortWriter {
                out: bytes.clone(),
                blocked,
            },
            true,
        );
        for value in 0u8..8 {
            stream.write_all(&[value]).await.unwrap();
            stream.flush().await.unwrap();
        }
        stream.write_all(b"ninth-raw").await.unwrap();
        stream.shutdown().await.unwrap();
        let (payloads, rest) = decode_written(&bytes.lock().unwrap(), 8);
        assert_eq!(
            payloads,
            (0u8..8).map(|byte| vec![byte]).collect::<Vec<_>>()
        );
        assert_eq!(rest, b"ninth-raw");
    }
    struct Chunks(VecDeque<u8>);
    impl AsyncWrite for Chunks {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncRead for Chunks {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if output.remaining() > 0
                && let Some(byte) = self.0.pop_front()
            {
                output.put_slice(&[byte]);
            }
            Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn empty_write_and_truncated_read_are_sticky_and_read_backpressure_is_independent() {
        let (wire, mut peer) = tokio::io::duplex(8);
        let mut stream = PaddedStream::new(wire, true);
        stream.write_all(&[0x55; 32]).await.unwrap(); // 已接受帧大于底层容量，read推进时将Pending。
        peer.write_all(b"\0\x02\0ok").await.unwrap();
        let mut reply = [0; 2];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_exact(&mut reply),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&reply, b"ok");
        let mut empty = ReadBuf::new(&mut []);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut cx, &mut empty)
                .is_ready()
        );
        peer.shutdown().await.unwrap();
        drop(peer);
        assert!(stream.flush().await.is_err());
        assert!(stream.write(b"not-recoverable").await.is_err());
        let mut truncated = PaddedStream::new(Chunks(VecDeque::from([0, 3, 0, 1])), true);
        assert!(truncated.read_to_end(&mut Vec::new()).await.is_err());
        assert!(truncated.write(b"late").await.is_err());
        assert!(truncated.flush().await.is_err());
    }

    #[tokio::test]
    async fn write_then_read_without_flush_and_fin_preserve_reverse_data() {
        let (wire, mut peer) = tokio::io::duplex(65536);
        let mut client = PaddedStream::new(wire, true);
        let task = tokio::spawn(async move {
            let mut header = [0; 3];
            peer.read_exact(&mut header).await.unwrap();
            let size = u16::from_be_bytes([header[0], header[1]]) as usize;
            let mut body = vec![0; size + header[2] as usize];
            peer.read_exact(&mut body).await.unwrap();
            assert_eq!(&body[..size], b"request");
            peer.write_all(b"\0\x05\0reply").await.unwrap();
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
            peer.write_all(b"\0\x09\0after-fin").await.unwrap();
            peer.shutdown().await.unwrap();
        });
        client.write_all(b"request").await.unwrap(); // 不显式flush：read必须推进已接受块。
        let mut reply = [0; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.read_exact(&mut reply),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&reply, b"reply");
        client.shutdown().await.unwrap();
        assert!(client.write(b"late").await.is_err());
        let mut tail = Vec::new();
        client.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"after-fin");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn split_headers_padding_and_ninth_raw_read_are_aligned() {
        let mut wire = Vec::new();
        for value in 0u8..8 {
            wire.extend([0, 1, 2, value, 0, 0]);
        }
        wire.extend(b"ninth-raw");
        let mut stream = PaddedStream::new(Chunks(wire.into()), true);
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(
            payload,
            [vec![0, 1, 2, 3, 4, 5, 6, 7], b"ninth-raw".to_vec()].concat()
        );
    }
    #[tokio::test]
    async fn truncated_padding_fails_and_zero_capacity_read_consumes_nothing() {
        let mut stream = PaddedStream::new(Chunks(VecDeque::from([0, 1, 2, 7, 0])), true);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut empty = ReadBuf::new(&mut []);
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut cx, &mut empty)
                .is_ready()
        );
        assert_eq!(stream.inner.0.len(), 5);
        let mut result = Vec::new();
        assert_eq!(
            stream.read_to_end(&mut result).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
