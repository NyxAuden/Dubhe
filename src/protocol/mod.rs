pub mod address;
pub mod http;
pub(crate) mod shadowsocks;
pub(crate) mod snell;
pub(crate) mod snell_v6;
pub mod socks5;
pub mod trojan;
pub mod vision;
pub mod vless;
pub(crate) mod vmess;
pub mod xudp;

#[cfg(test)]
pub(crate) mod test_io {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    // 用独立线字节模拟逐字节拆包，并保存服务端应答与未消费载荷。
    pub struct Wire {
        input: Vec<u8>,
        offset: usize,
        chunk: usize,
        pub output: Vec<u8>,
        pub closed: bool,
    }

    impl Wire {
        pub fn new(input: impl Into<Vec<u8>>) -> Self {
            Self {
                input: input.into(),
                offset: 0,
                chunk: usize::MAX,
                output: Vec::new(),
                closed: false,
            }
        }

        pub fn fragmented(mut self) -> Self {
            self.chunk = 1;
            self
        }

        pub fn remaining(&self) -> &[u8] {
            &self.input[self.offset..]
        }
    }

    impl AsyncRead for Wire {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let count = buf.remaining().min(self.chunk).min(self.remaining().len());
            buf.put_slice(&self.remaining()[..count]);
            self.offset += count;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Wire {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.output.extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.closed = true;
            Poll::Ready(Ok(()))
        }
    }
}
