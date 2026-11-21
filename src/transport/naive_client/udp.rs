//! Naive上的正式UoT v2 connect模式；每目标独立连接，空报文保留。
use super::*;
use crate::transport::tunnel_udp::DatagramSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Session {
    stream: Upstream,
    input: Vec<u8>,
    maximum: usize,
    failed: bool,
}
pub(crate) async fn open(
    ctx: &Context,
    proxy: &ProxyOutbound,
    target: &Target,
) -> io::Result<Box<dyn DatagramSession>> {
    if !options(proxy)?.udp_over_tcp || proxy.via.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Naive UDP需要显式UoT且不支持via",
        ));
    }
    authority(target)?; // 正常业务目标不能使用0端口占位。
    if target.port == 0 {
        return Err(invalid("UoT业务目标端口无效"));
    }
    // 复用已有SOCKS地址编码器，去掉UDP ASSOCIATE前缀，不自造地址码。
    let address = crate::outbound::socks5_udp_encode(target, &[])?;
    let mut request = vec![1]; // v2 isConnect=true。
    request.extend_from_slice(&address[3..]);
    let magic = Target {
        host: Host::Domain(UOT_HOST.into()),
        port: 0,
    };
    let mut stream = connect(ctx, proxy, &magic).await?;
    stream.write_all(&request).await?;
    stream.flush().await?;
    Ok(Box::new(Session {
        stream,
        input: Vec::new(),
        maximum: ctx.limits.max_udp_payload.min(65535),
        failed: false,
    }))
}

impl DatagramSession for Session {
    fn send<'a>(
        &'a mut self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if self.failed {
                return Err(closed());
            }
            if payload.len() > self.maximum {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Naive UoT报文超过上限",
                ));
            }
            // 写入开始后若被取消，不得在半帧后继续发送下一报文或追加FIN。
            self.failed = true;
            self.stream
                .write_all(&(payload.len() as u16).to_be_bytes())
                .await?;
            self.stream.write_all(payload).await?;
            self.stream.flush().await?;
            self.failed = false;
            Ok(())
        })
    }
    fn recv(&mut self) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            if self.failed {
                return Err(closed());
            }
            let result = async {
                loop {
                    let needed = if self.input.len() < 2 {
                        2
                    } else {
                        let length = u16::from_be_bytes([self.input[0], self.input[1]]) as usize;
                        if length > self.maximum {
                            return Err(invalid("Naive UoT响应超过上限"));
                        }
                        if self.input.len() == length + 2 {
                            let payload = self.input[2..].to_vec();
                            self.input.clear();
                            return Ok(payload);
                        }
                        length + 2
                    };
                    let mut bytes = [0; 4096];
                    let count = (needed - self.input.len()).min(bytes.len());
                    let count = self.stream.read(&mut bytes[..count]).await?;
                    if count == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Naive UoT流结束或帧截断",
                        ));
                    }
                    self.input.extend_from_slice(&bytes[..count]);
                }
            }
            .await;
            if result.is_err() {
                self.failed = true;
            }
            result
        })
    }
    fn close(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            if !self.failed {
                let _ = self.stream.shutdown().await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    const WAIT: Duration = Duration::from_secs(3);

    struct Gate {
        inner: tokio::io::DuplexStream,
        blocked: Arc<AtomicBool>,
    }
    impl AsyncRead for Gate {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, output)
        }
    }
    impl AsyncWrite for Gate {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.blocked.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            let count = bytes.len().min(1);
            Pin::new(&mut self.inner).poll_write(cx, &bytes[..count])
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }
    #[tokio::test]
    async fn receive_split_length_payload_cancel_empty_and_oversize_keep_exact_cursor() {
        let (wire, mut peer) = tokio::io::duplex(65536);
        let mut session = Session {
            stream: Upstream::new_send(wire, None),
            input: Vec::new(),
            maximum: 16,
            failed: false,
        };
        peer.write_all(&[0]).await.unwrap();
        assert!(
            timeout(Duration::from_millis(10), session.recv())
                .await
                .is_err()
        );
        assert_eq!(session.input, [0]);
        peer.write_all(&[3, b'a']).await.unwrap();
        assert!(
            timeout(Duration::from_millis(10), session.recv())
                .await
                .is_err()
        );
        assert_eq!(session.input, [0, 3, b'a']);
        peer.write_all(b"bc\0\0").await.unwrap();
        assert_eq!(session.recv().await.unwrap(), b"abc");
        assert!(session.recv().await.unwrap().is_empty());
        assert_eq!(
            session.send(&[0; 17]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        session.send(b"ok").await.unwrap();
        let mut sent = [0; 4];
        peer.read_exact(&mut sent).await.unwrap();
        assert_eq!(&sent, b"\0\x02ok");
        peer.write_all(&[0, 17]).await.unwrap();
        assert!(session.recv().await.is_err());
        assert!(session.failed);
        assert!(session.send(b"late").await.is_err());
    }
    #[tokio::test]
    async fn cancelled_partial_send_cannot_continue_or_append_fin() {
        let (wire, mut peer) = tokio::io::duplex(1);
        let blocked = Arc::new(AtomicBool::new(false));
        let stream = Upstream::new_send(
            Gate {
                inner: wire,
                blocked: blocked.clone(),
            },
            None,
        );
        let mut session = Session {
            stream,
            input: Vec::new(),
            maximum: 65535,
            failed: false,
        };
        assert!(
            timeout(Duration::from_millis(10), session.send(b"blocked-payload"))
                .await
                .is_err()
        );
        assert!(session.failed);
        session.close().await;
        assert!(session.send(b"different").await.is_err());
        drop(session);
        let mut bytes = Vec::new();
        timeout(WAIT, peer.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes, [0], "只保留已实际写出的半长度，不能补FIN或新数据");
    }
}
