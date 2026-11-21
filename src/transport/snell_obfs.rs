//! 固定 sing-snell 的 HTTP/TLS obfs。仅是外观承载，不是 TLS 或 WebSocket。
//! 首读/首写状态由实例拥有，短写与取消不会重复首消息或丢失半个头。
use std::{
    io,
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll, ready},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_HTTP_HEAD: usize = 8192;
const MAX_WRITE: usize = 16 * 1024;
const CLIENT_PREFIX: usize = 0x8e;
const SERVER_PREFIX: usize = 0x6b;
const CLIENT_TRAILER: usize = 0x42;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Mode {
    #[default]
    None,
    Http,
    Tls,
}
impl Mode {
    pub(crate) fn parse(name: Option<&str>) -> io::Result<Self> {
        match name.unwrap_or("none").to_ascii_lowercase().as_str() {
            "" | "none" => Ok(Self::None),
            "http" => Ok(Self::Http),
            "tls" => Ok(Self::Tls),
            _ => Err(invalid_input("Snell obfs_mode仅支持none/http/tls")),
        }
    }
}

pub(crate) fn validate(
    version: u8,
    name: Option<&str>,
    host: Option<&str>,
    uri: Option<&str>,
) -> io::Result<Mode> {
    let mode = Mode::parse(name)?;
    if version == 6 && mode != Mode::None {
        return Err(invalid_input("Snell v6不提供HTTP/TLS obfs"));
    }
    if mode == Mode::None && (host.is_some() || uri.is_some()) {
        return Err(invalid_input("未启用Snell obfs不得配置host/uri"));
    }
    if mode != Mode::Http && uri.is_some() {
        return Err(invalid_input("obfs_uri仅适用于HTTP obfs"));
    }
    if host.is_some_and(|value| {
        value.is_empty()
            || value.len() > 253
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'/' | b'\\'))
    }) {
        return Err(invalid_input(
            "Snell obfs_host必须是有界可见ASCII，不能注入头部",
        ));
    }
    if uri.is_some_and(|value| {
        !value.starts_with('/')
            || value.len() > 1024
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
    }) {
        return Err(invalid_input("Snell HTTP obfs_uri无效"));
    }
    Ok(mode)
}
fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| io::Error::other("Snell obfs随机源失败"))?;
    Ok(bytes)
}
fn unix_time() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

/// 两个方向共享底层流，读写状态分离；每次最多接受16KiB业务，无后台任务。
pub(crate) struct Stream<S> {
    inner: S,
    mode: Mode,
    client: bool,
    host: String,
    uri: String,
    first_write: bool,
    pending: Vec<u8>,
    pending_pos: usize,
    input: Vec<u8>,
    first_read: bool,
    remaining: usize,
    trailer: bool,
    eof: bool,
    write_closed: bool,
    failure: Option<io::ErrorKind>,
}
impl<S> Stream<S> {
    pub(crate) fn server(inner: S, mode: Mode) -> Self {
        Self::new(inner, mode, false, None, None)
    }
    pub(crate) fn client(inner: S, mode: Mode, host: Option<&str>, uri: Option<&str>) -> Self {
        Self::new(inner, mode, true, host, uri)
    }
    fn new(inner: S, mode: Mode, client: bool, host: Option<&str>, uri: Option<&str>) -> Self {
        Self {
            inner,
            mode,
            client,
            host: host
                .unwrap_or(if mode == Mode::Tls {
                    "cloudfront.net"
                } else {
                    "bing.com"
                })
                .to_owned(),
            uri: uri.unwrap_or("/").to_owned(),
            first_write: true,
            pending: Vec::new(),
            pending_pos: 0,
            input: Vec::new(),
            first_read: true,
            remaining: 0,
            trailer: false,
            eof: false,
            write_closed: false,
            failure: None,
        }
    }
}

impl<S: AsyncRead + Unpin> Stream<S> {
    /// 精确读取本阶段需要的字节，有限缓冲保存在实例中，不超读下一阶段。
    fn fill(&mut self, cx: &mut Context<'_>, needed: usize) -> Poll<io::Result<bool>> {
        while self.input.len() < needed {
            let mut bytes = [0; 1024];
            let count = (needed - self.input.len()).min(bytes.len());
            let mut read = ReadBuf::new(&mut bytes[..count]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                return Poll::Ready(Ok(false));
            }
            self.input.extend_from_slice(read.filled());
        }
        Poll::Ready(Ok(true))
    }
    fn read_tls(&mut self, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut records = 0;
        loop {
            if self.remaining > 0 {
                let count = self.remaining.min(output.remaining());
                let mut read = ReadBuf::new(output.initialize_unfilled_to(count));
                ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read))?;
                let count = read.filled().len();
                if count == 0 {
                    return Poll::Ready(Err(invalid("Snell TLS obfs载荷截断")));
                }
                output.advance(count);
                self.remaining -= count;
                return Poll::Ready(Ok(()));
            }
            if self.trailer {
                // 客户端首payload之后是SNI扩展9字节头、hostname和固定66字节尾。
                if !ready!(self.fill(cx, 9))? {
                    return Poll::Ready(Err(invalid("Snell TLS obfs SNI头截断")));
                }
                let length = usize::from(u16::from_be_bytes([self.input[7], self.input[8]]));
                if length > 253 {
                    return Poll::Ready(Err(invalid("Snell TLS obfs SNI过长")));
                }
                if !ready!(self.fill(cx, 9 + length + CLIENT_TRAILER))? {
                    return Poll::Ready(Err(invalid("Snell TLS obfs尾部截断")));
                }
                self.input.clear();
                self.trailer = false;
            }
            let size = if self.first_read {
                if self.client {
                    SERVER_PREFIX
                } else {
                    CLIENT_PREFIX
                }
            } else {
                5
            };
            if !ready!(self.fill(cx, size))? {
                if !self.first_read && self.input.is_empty() {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(invalid("Snell TLS obfs记录头截断")));
            }
            let header = &self.input;
            if header[0] != if self.first_read { 0x16 } else { 0x17 } || header[1] != 3 {
                return Poll::Ready(Err(invalid("Snell TLS obfs记录类型无效")));
            }
            let length = usize::from(u16::from_be_bytes([header[size - 2], header[size - 1]]));
            if self.first_read {
                if self.client {
                    if length > MAX_WRITE {
                        return Poll::Ready(Err(invalid("Snell TLS obfs首响应过长")));
                    }
                } else {
                    if length > 0x400 {
                        return Poll::Ready(Err(invalid("Snell TLS obfs首请求过长")));
                    }
                    self.trailer = true;
                }
                self.first_read = false;
            } else if length > MAX_WRITE {
                return Poll::Ready(Err(invalid("Snell TLS obfs记录过长")));
            }
            self.input.clear();
            self.remaining = length;
            // 零长度记录不等于业务EOF；有限让出，避免连续零记录占满执行线程。
            records += 1;
            if self.remaining == 0 && records >= 32 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    }

    fn receive(&mut self, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.mode {
            Mode::None => Pin::new(&mut self.inner).poll_read(cx, output),
            Mode::Tls => self.read_tls(cx, output),
            Mode::Http => {
                while self.first_read {
                    if self.input.len() >= MAX_HTTP_HEAD {
                        return Poll::Ready(Err(invalid("Snell HTTP obfs头过长")));
                    }
                    let needed = self.input.len() + 1;
                    if !ready!(self.fill(cx, needed))? {
                        return Poll::Ready(Err(invalid("Snell HTTP obfs头截断")));
                    }
                    if self.input.ends_with(b"\r\n\r\n") {
                        self.first_read = false;
                        self.input.clear();
                    }
                }
                Pin::new(&mut self.inner).poll_read(cx, output)
            }
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 || self.eof {
            return Poll::Ready(Ok(()));
        }
        if let Some(kind) = self.failure {
            return Poll::Ready(Err(io::Error::new(kind, "Snell obfs流已失败")));
        }
        // 先写后直接读也推进已接受的有界写批次，不要求调用方另起发送任务。
        if let Poll::Ready(Err(error)) = self.drain(cx) {
            return Poll::Ready(Err(error));
        }
        let result = self.receive(cx, output);
        if let Poll::Ready(Err(error)) = &result {
            self.failure = Some(error.kind());
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> Stream<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(kind) = self.failure {
            return Poll::Ready(Err(io::Error::new(kind, "Snell obfs流已失败")));
        }
        while self.pending_pos < self.pending.len() {
            match ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..])
            ) {
                Ok(0) => {
                    self.failure = Some(io::ErrorKind::WriteZero);
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Ok(count) => self.pending_pos += count,
                Err(error) => {
                    self.failure = Some(error.kind());
                    return Poll::Ready(Err(error));
                }
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.drain(cx))?;
        if self.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.mode == Mode::None {
            return Pin::new(&mut self.inner).poll_write(cx, bytes);
        }
        let count = bytes.len().min(MAX_WRITE);
        self.pending = match self.mode {
            Mode::Http if self.first_write => {
                http_first(self.client, &self.host, &self.uri, &bytes[..count])?
            }
            Mode::Http => bytes[..count].to_vec(),
            Mode::Tls if self.first_write => {
                if self.client {
                    client_hello(
                        &self.host,
                        &bytes[..count],
                        unix_time(),
                        random()?,
                        random()?,
                    )?
                } else {
                    server_hello(&bytes[..count], unix_time(), random()?, random()?)
                }
            }
            Mode::Tls => records(&bytes[..count]),
            Mode::None => unreachable!(),
        };
        self.first_write = false;
        // 有界缓冲接受后立即尝试排空；Pending保留游标，后续write/read/flush继续。
        // 错误已由drain永久记录，不能在下一次不同buffer上重复写首头。
        let _ = self.drain(cx);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        self.write_closed = true;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct HttpFingerprint {
    key: String,
    user_agent: String,
}
fn http_first(client: bool, host: &str, uri: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    static CLIENT: OnceLock<HttpFingerprint> = OnceLock::new();
    static SERVER: OnceLock<String> = OnceLock::new();
    let head = if client {
        if CLIENT.get().is_none() {
            let selector: [u8; 2] = random()?;
            let _ = CLIENT.set(HttpFingerprint { key: STANDARD.encode(random::<16>()?), user_agent: format!("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.{}; rv:64.0) Gecko/20100101 Firefox/{}.0", 9 + selector[0] % 6, 22 + selector[1] % 43) });
        }
        let fingerprint = CLIENT.get().expect("进程内指纹已设置");
        format!(
            "GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: {}\r\nSec-WebSocket-Key: {}\r\n\r\n",
            fingerprint.user_agent,
            payload.len(),
            fingerprint.key
        )
    } else {
        if SERVER.get().is_none() {
            let selector: [u8; 2] = random()?;
            let _ = SERVER.set(format!("HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.{}.{}\r\nDate: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", selector[0] % 14, selector[1] % 12, http_date(), STANDARD.encode(random::<16>()?)));
        }
        SERVER.get().expect("进程内响应已设置").clone()
    };
    let mut wire = head.into_bytes();
    wire.extend_from_slice(payload);
    Ok(wire)
}
fn http_date() -> String {
    // 复用已锁定依赖的日期类型，不新增核心依赖；时间只用于首头外观。
    let time = x509_parser::time::ASN1Time::now().to_datetime();
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DAYS[time.weekday().number_days_from_monday() as usize],
        time.day(),
        MONTHS[time.month() as usize - 1],
        time.year(),
        time.hour(),
        time.minute(),
        time.second()
    )
}

fn records(payload: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(payload.len() + payload.len().div_ceil(MAX_WRITE) * 5);
    for chunk in payload.chunks(MAX_WRITE) {
        wire.extend_from_slice(&[0x17, 3, 3]);
        wire.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        wire.extend_from_slice(chunk);
    }
    wire
}

const CIPHERS: &[u8] = &[
    0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
    0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
    0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
    0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
];
const TRAILER: &[u8] = &[
    0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d,
    0x00, 0x17, 0x00, 0x19, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02,
    0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
    0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17,
    0x00, 0x00,
];
fn client_hello(
    host: &str,
    payload: &[u8],
    timestamp: u32,
    random: [u8; 28],
    session: [u8; 32],
) -> io::Result<Vec<u8>> {
    validate(4, Some("tls"), Some(host), None)?;
    let first = &payload[..payload.len().min(0x400)];
    let mut wire = vec![0x16, 3, 1];
    wire.extend_from_slice(&((0xd4 + host.len() + first.len()) as u16).to_be_bytes());
    wire.extend_from_slice(&[1, 0]);
    wire.extend_from_slice(&((0xd0 + host.len() + first.len()) as u16).to_be_bytes());
    wire.extend_from_slice(&[3, 3]);
    wire.extend_from_slice(&timestamp.to_be_bytes());
    wire.extend_from_slice(&random);
    wire.push(0x20);
    wire.extend_from_slice(&session);
    wire.extend_from_slice(&[0, 0x38]);
    wire.extend_from_slice(CIPHERS);
    wire.extend_from_slice(&[1, 0]);
    wire.extend_from_slice(&((0x4f + host.len() + first.len()) as u16).to_be_bytes());
    wire.extend_from_slice(&[0, 0x23]);
    wire.extend_from_slice(&(first.len() as u16).to_be_bytes());
    wire.extend_from_slice(first);
    wire.extend_from_slice(&[0, 0]);
    wire.extend_from_slice(&((host.len() + 5) as u16).to_be_bytes());
    wire.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    wire.push(0);
    wire.extend_from_slice(&(host.len() as u16).to_be_bytes());
    wire.extend_from_slice(host.as_bytes());
    wire.extend_from_slice(TRAILER);
    wire.extend(records(&payload[first.len()..]));
    Ok(wire)
}
fn server_hello(payload: &[u8], timestamp: u32, random: [u8; 28], session: [u8; 32]) -> Vec<u8> {
    let first = &payload[..payload.len().min(MAX_WRITE)];
    let mut wire = vec![0x16, 3, 1, 0, 91, 2, 0, 0, 0x57, 3, 3];
    wire.extend_from_slice(&timestamp.to_be_bytes());
    wire.extend_from_slice(&random);
    wire.push(0x20);
    wire.extend_from_slice(&session);
    wire.extend_from_slice(&[
        0xcc, 0xa8, 0, 0, 0, 0xff, 1, 0, 1, 0, 0, 0x17, 0, 0, 0, 0x0b, 0, 2, 1, 0, 0x14, 3, 3, 0,
        1, 1, 0x16, 3, 3,
    ]);
    wire.extend_from_slice(&(first.len() as u16).to_be_bytes());
    wire.extend_from_slice(first);
    wire.extend(records(&payload[first.len()..]));
    wire
}

#[cfg(test)]
mod tests;
