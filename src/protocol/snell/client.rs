//! Snell 正式出站：复用入站记录 codec，不复制 KDF/AEAD。
//! TCP 以拥有记录状态的 future 适配 AsyncRead/Write，Pending/取消不丢游标。
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::*;
use crate::{
    config::SnellClientOptions, forward::Upstream, transport::tunnel_udp::DatagramSession,
};

type Rx = Reader<ReadHalf<Upstream>>;
type Tx = Writer<WriteHalf<Upstream>>;
type Reading = Pin<Box<dyn Future<Output = io::Result<(Rx, Option<Vec<u8>>)>> + Send>>;
type Writing = Pin<Box<dyn Future<Output = (Tx, io::Result<()>)> + Send>>;

fn request(options: &SnellClientOptions, target: Option<&Target>) -> io::Result<Vec<u8>> {
    let key = options
        .userkey
        .as_ref()
        .map_or(&[][..], |key| key.0.as_bytes());
    let mut bytes = vec![
        REQUEST_VERSION,
        if target.is_some() {
            COMMAND_CONNECT_V2
        } else {
            COMMAND_UDP
        },
        key.len() as u8,
    ];
    bytes.extend_from_slice(key);
    if let Some(target) = target {
        let host = match &target.host {
            Host::Ip(ip) => ip.to_string(),
            Host::Domain(host) => host.clone(),
        };
        if target.port == 0
            || host.is_empty()
            || host.len() > 255
            || !host.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Snell目标地址无效",
            ));
        }
        bytes.push(host.len() as u8);
        bytes.extend_from_slice(host.as_bytes());
        bytes.extend_from_slice(&target.port.to_be_bytes());
    }
    Ok(bytes)
}

fn reply(bytes: &[u8]) -> io::Result<Vec<u8>> {
    match bytes.first() {
        Some(&REPLY_TUNNEL) => Ok(bytes[1..].to_vec()),
        Some(&REPLY_ERROR) if bytes.len() >= 3 && bytes.len() == 3 + usize::from(bytes[2]) => {
            // 对端错误文本不受信，不输出其正文，也不把拒绝当连接成功。
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Snell上游拒绝目标",
            ))
        }
        _ => Err(invalid("Snell上游应答无效")),
    }
}

async fn begin(
    stream: Upstream,
    options: &SnellClientOptions,
    target: Option<&Target>,
) -> io::Result<(ReadHalf<Upstream>, Tx)> {
    options
        .validate()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Snell出站参数无效"))?;
    let bytes = request(options, target)?;
    let mode = options.record_mode();
    let obfs = crate::transport::snell_obfs::Mode::parse(options.obfs_mode.as_deref())?;
    let stream = if obfs != crate::transport::snell_obfs::Mode::None {
        let local = stream.local_addr().ok();
        Upstream::new_send(
            crate::transport::snell_obfs::Stream::client(
                stream,
                obfs,
                options.obfs_host.as_deref(),
                options.obfs_uri.as_deref(),
            ),
            local,
        )
    } else {
        stream
    };
    let (read, write) = tokio::io::split(stream);
    let mut direction = TunnelIo::new(write, mode);
    let writer = direction.writer(options.psk.0.as_bytes()).await?;
    // 请求头必须完整落在首记录；合法的长userkey/域名不能被流量整形切成半个请求。
    // 使用既有单记录编码，仍为同一正式记录格式并推进shaped状态，不改wire字段。
    writer.write_packet(&bytes).await?;
    writer.flush().await?;
    Ok((read, direction.writer.take().expect("写方向已初始化")))
}

async fn read_reply(read: ReadHalf<Upstream>, mode: Mode, psk: &[u8]) -> io::Result<(Rx, Vec<u8>)> {
    let mut reader = match mode {
        Mode::Shaped | Mode::Unshaped => {
            Reader::Aead(RecordReader::new(read, psk, mode == Mode::Shaped).await?)
        }
        Mode::Default => Reader::ShapedV6(ShapedV6Reader::new(read, psk)),
        Mode::UnsafeRaw => Reader::Raw(RawReader::new(read)),
    };
    let first = reader
        .read_record()
        .await?
        .ok_or_else(|| invalid("Snell首应答为零块"))?;
    let cached = reply(&first)?;
    Ok((reader, cached))
}

pub(crate) async fn connect(
    stream: Upstream,
    options: &SnellClientOptions,
    target: &Target,
) -> io::Result<ClientStream> {
    let (read, write) = begin(stream, options, Some(target)).await?;
    let maximum = write.max_payload();
    let mode = options.record_mode();
    let psk = options.psk.0.as_bytes().to_vec();
    // 固定上游可将ReplyTunnel与目标首次响应合并，必须先允许业务写入。
    // future从salt开始拥有整个首应答解析，外层read取消后仍保留已读位置。
    let reading: Reading = Box::pin(async move {
        let (reader, cached) = read_reply(read, mode, &psk).await?;
        Ok((reader, Some(cached)))
    });
    Ok(ClientStream {
        read: None,
        write: Some(write),
        reading: Some(reading),
        writing: None,
        cached: Vec::new(),
        offset: 0,
        maximum,
        read_eof: false,
        flushing: false,
        shutdown_started: false,
        shutdown_done: false,
        reply_read: false,
        failure: None,
    })
}

pub(crate) struct ClientStream {
    read: Option<Rx>,
    write: Option<Tx>,
    reading: Option<Reading>,
    writing: Option<Writing>,
    cached: Vec<u8>,
    offset: usize,
    maximum: usize,
    read_eof: bool,
    flushing: bool,
    shutdown_started: bool,
    shutdown_done: bool,
    reply_read: bool,
    failure: Option<io::ErrorKind>,
}

pub(crate) mod reuse;

impl ClientStream {
    /// 只能在双向逻辑FIN完成后开启下一请求；保留记录salt/nonce与外层obfs。
    async fn restart(&mut self, options: &SnellClientOptions, target: &Target) -> io::Result<()> {
        self.failed()?;
        if !self.reply_read
            || !self.read_eof
            || !self.shutdown_done
            || self.reading.is_some()
            || self.writing.is_some()
        {
            return Err(invalid("Snell旧逻辑流尚未完成"));
        }
        let bytes = request(options, Some(target))?;
        self.write
            .as_mut()
            .expect("已完成写方向")
            .write_packet(&bytes)
            .await?;
        let mut reader = self.read.take().expect("已完成读方向");
        self.reading = Some(Box::pin(async move {
            let first = reader
                .read_record()
                .await?
                .ok_or_else(|| invalid("Snell首应答为零块"))?;
            let cached = reply(&first)?;
            Ok((reader, Some(cached)))
        }));
        self.cached.clear();
        self.offset = 0;
        self.read_eof = false;
        self.flushing = false;
        self.shutdown_started = false;
        self.shutdown_done = false;
        self.reply_read = false;
        Ok(())
    }

    fn failed(&self) -> io::Result<()> {
        match self.failure {
            Some(kind) => Err(io::Error::new(kind, "Snell流已失败")),
            None => Ok(()),
        }
    }
    fn poll_written(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.failed()?;
        if let Some(future) = self.writing.as_mut() {
            let (writer, result) = std::task::ready!(future.as_mut().poll(cx));
            self.writing = None;
            self.write = Some(writer);
            if let Err(error) = result {
                self.failure = Some(error.kind());
                return Poll::Ready(Err(error));
            }
        }
        Poll::Ready(Ok(()))
    }
    fn queue(&mut self, action: Action) {
        let mut writer = self.write.take().expect("写任务互斥");
        self.writing = Some(Box::pin(async move {
            let result = match action {
                Action::Data(bytes) => writer.write_data(&bytes).await,
                Action::Flush => writer.flush().await,
                Action::Finish => {
                    async {
                        writer.write_zero().await?;
                        writer.flush().await
                    }
                    .await
                }
            };
            (writer, result)
        }));
    }
}

enum Action {
    Data(Vec<u8>),
    Flush,
    Finish,
}

impl AsyncRead for ClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.failed()?;
        // 用户可在write后直接read；即使未显式flush，也推进已经接受的有界写任务。
        // Pending写不能阻止独立的反向读取，但其waker仍保证后续进度。
        if let Poll::Ready(Err(error)) = self.poll_written(cx) {
            return Poll::Ready(Err(error));
        }
        loop {
            if self.offset < self.cached.len() {
                let length = output.remaining().min(self.cached.len() - self.offset);
                output.put_slice(&self.cached[self.offset..self.offset + length]);
                self.offset += length;
                return Poll::Ready(Ok(()));
            }
            if self.read_eof {
                return Poll::Ready(Ok(()));
            }
            if self.reading.is_none() {
                let mut reader = self.read.take().expect("读任务互斥");
                self.reading = Some(Box::pin(async move {
                    let result = reader.read_record().await;
                    result.map(|record| (reader, record))
                }));
            }
            let result = std::task::ready!(
                self.reading
                    .as_mut()
                    .expect("读任务已创建")
                    .as_mut()
                    .poll(cx)
            );
            self.reading = None;
            match result {
                Ok((reader, record)) => {
                    self.reply_read = true;
                    self.read = Some(reader);
                    match record {
                        Some(bytes) => {
                            self.cached = bytes;
                            self.offset = 0;
                        }
                        None => {
                            self.cached.clear();
                            self.read_eof = true;
                        }
                    }
                }
                Err(error) => {
                    self.failure = Some(error.kind());
                    return Poll::Ready(Err(error));
                }
            }
        }
    }
}
impl AsyncWrite for ClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        std::task::ready!(self.poll_written(cx))?;
        if self.shutdown_started {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Snell写方向已关闭",
            )));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let length = bytes.len().min(self.maximum);
        self.flushing = false;
        self.queue(Action::Data(bytes[..length].to_vec()));
        // 接受一个有界记录；未发送字节由实例中的future拥有，flush/下次write排空。
        Poll::Ready(Ok(length))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_written(cx))?;
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        if !self.flushing {
            self.flushing = true;
            self.queue(Action::Flush);
        }
        // Pending中的flush由同一个future确认，不能每次poll重建屏障。
        std::task::ready!(self.poll_written(cx))?;
        self.flushing = false;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_written(cx))?;
        if self.shutdown_done {
            return Poll::Ready(Ok(()));
        }
        if !self.shutdown_started {
            self.shutdown_started = true;
            self.queue(Action::Finish);
        }
        std::task::ready!(self.poll_written(cx))?;
        self.shutdown_done = true;
        // 不关闭承载的读方向；零块是正式逻辑流FIN，反向仍可有数据。
        Poll::Ready(Ok(()))
    }
}

pub(crate) struct UdpSession {
    read: Rx,
    write: Tx,
    target: Target,
    prefix: Vec<u8>,
    failure: bool,
}

pub(crate) async fn open_udp(
    stream: Upstream,
    options: &SnellClientOptions,
    target: &Target,
) -> io::Result<UdpSession> {
    if target.port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Snell UDP目标端口无效",
        ));
    }
    let mut prefix = vec![UDP_COMMAND_FORWARD];
    match &target.host {
        Host::Ip(ip) => {
            prefix.push(0);
            encode_udp_response_address(SocketAddr::new(*ip, target.port), &mut prefix);
        }
        Host::Domain(host) => {
            if host.is_empty()
                || host.len() > 255
                || !host.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Snell UDP域名无效",
                ));
            }
            prefix.push(host.len() as u8);
            prefix.extend_from_slice(host.as_bytes());
            prefix.extend_from_slice(&target.port.to_be_bytes());
        }
    }
    let (raw, write) = begin(stream, options, None).await?;
    let (read, cached) = read_reply(raw, options.record_mode(), options.psk.0.as_bytes()).await?;
    if !cached.is_empty() {
        return Err(invalid("Snell UDP首应答含多余数据"));
    }
    Ok(UdpSession {
        read,
        write,
        target: target.clone(),
        prefix,
        failure: false,
    })
}
#[cfg(test)]
mod tests;

impl DatagramSession for UdpSession {
    fn send<'a>(
        &'a mut self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if self.failure {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Snell UDP流已失败",
                ));
            }
            if self.prefix.len() + payload.len() > self.write.max_payload() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Snell UDP数据报超过单记录上限",
                ));
            }
            let mut frame = self.prefix.clone();
            frame.extend_from_slice(payload);
            // wire写入开始后若future被取消，不能在半帧后继续复用或追加FIN。
            self.failure = true;
            let result = async {
                self.write.write_packet(&frame).await?;
                self.write.flush().await
            }
            .await;
            if result.is_ok() {
                self.failure = false;
            }
            result
        })
    }
    fn recv(&mut self) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            loop {
                let frame = self.read.read_record().await?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "Snell UDP流结束")
                })?;
                let mut cursor = Cursor::new(&frame);
                let ip = match cursor.u8()? {
                    ADDRESS_TYPE_IPV4 => IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(cursor.bytes(4)?).expect("长度已核查"),
                    )),
                    ADDRESS_TYPE_IPV6 => IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(cursor.bytes(16)?).expect("长度已核查"),
                    )),
                    _ => return Err(invalid("Snell UDP来源地址无效")),
                };
                let port = cursor.u16_be()?;
                if port != self.target.port
                    || matches!(self.target.host, Host::Ip(expected) if expected != ip)
                {
                    continue;
                }
                return Ok(cursor.remaining().to_vec());
            }
        })
    }
    fn close(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            if !self.failure {
                let _ = self.write.write_zero().await;
                let _ = self.write.flush().await;
            }
        })
    }
}
