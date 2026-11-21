//! Shadowsocks AEAD 2022 header protocol

use std::io;

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::relay::Address;

/// Maximum padding length
pub const MAX_PADDING_SIZE: usize = 900;

/// Stream (Client & Server) timestamp max differences (ABS)
pub const SERVER_STREAM_TIMESTAMP_MAX_DIFF: u64 = 30;

/// TCP Request Header
///
/// +-------+-------+-------+-------+-------+-------+-------+-------+-------+
/// | ADDR (Variable ...)
/// +-------+-------+-------+-------+-------+-------+-------+-------+-------+
/// | PADDING SIZE  | PADDING (Variable ...)
/// +-------+-------+-------+-------+-------+-------+-------+-------+-------+
#[derive(Debug, Clone)]
pub struct Aead2022TcpRequestHeader {
    pub addr: Address,
    pub padding_size: u16,
}

impl Aead2022TcpRequestHeader {
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let addr = Address::read_from(reader).await?;

        let mut padding_size_buffer = [0u8; 2];
        reader.read_exact(&mut padding_size_buffer).await?;

        let padding_size = u16::from_be_bytes(padding_size_buffer);
        // 本内核补丁：输入也遵守900字节上限，且不能把截断padding当作正常EOF。
        if usize::from(padding_size) > MAX_PADDING_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "padding exceeds 900 bytes",
            ));
        }
        let mut padding = [0u8; MAX_PADDING_SIZE];
        reader
            .read_exact(&mut padding[..usize::from(padding_size)])
            .await?;

        Ok(Self { addr, padding_size })
    }

    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        Aead2022TcpRequestHeaderRef {
            addr: &self.addr,
            padding_size: self.padding_size,
        }
        .write_to_buf(buf)
    }

    pub fn serialized_len(&self) -> usize {
        Aead2022TcpRequestHeaderRef {
            addr: &self.addr,
            padding_size: self.padding_size,
        }
        .serialized_len()
    }
}

#[derive(Debug)]
pub struct Aead2022TcpRequestHeaderRef<'a> {
    pub addr: &'a Address,
    pub padding_size: u16,
}

impl Aead2022TcpRequestHeaderRef<'_> {
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        assert!(
            self.padding_size as usize <= MAX_PADDING_SIZE,
            "padding length must be in [0, {MAX_PADDING_SIZE}]"
        );

        buf.put_u16(self.padding_size);
        if self.padding_size > 0 {
            unsafe {
                buf.advance_mut(self.padding_size as usize);
            }
        }
    }

    pub fn serialized_len(&self) -> usize {
        self.addr.serialized_len() + 2 + self.padding_size as usize
    }
}
