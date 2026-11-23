//! ShadowTLS v3 服务端。
//!
//! 外层会话与真实的 TLS 1.3 域名完成握手，但握手后不承载真实 TLS 业务：
//! 客户端在 TLS 外观的记录里写入带 HMAC 的内层协议流。服务端只在首个合法
//! 客户端记录出现后停止转发，把去除记录层的明文流交给同进程 detour 入站。
//!
//! 与上游 `sagernet/sing-shadowtls` v3 一致的要点：
//! - ClientHello 的 session_id 末 4 字节为 HMAC-SHA1(password, ClientHello
//!   去掉该 4 字节并补 0) 的前 4 字节；
//! - 认证成功后以真实握手服务器的 server_random 派生 HMAC 链；
//! - 握手期服务器 application_data 需要 XOR(SHA256(password||server_random))
//!   并追加 HMAC；
//! - 认证完成后每条记录为 `[23,3,3,len][4字节HMAC][payload]`。
//!
//! 本实现支持 `handshake_for_server_name` 与 wildcard SNI；v1/v2 不支持。
//! 未认证流量原样回落到伪装握手服务器。

use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use aws_lc_rs::{
    digest,
    hmac::{Context as HmacContext, HMAC_SHA1_FOR_LEGACY_USE_ONLY, Key},
    rand,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::timeout,
};

use crate::{forward, session::Target, transport::DetourStream};

mod client;

pub(crate) use client::ShadowTlsClient;

const TLS_HEADER_SIZE: usize = 5;
const HMAC_SIZE: usize = 4;
const TLS_HMAC_HEADER_SIZE: usize = TLS_HEADER_SIZE + HMAC_SIZE;
const TLS_RANDOM_SIZE: usize = 32;
const TLS_SESSION_ID_SIZE: usize = 32;
const SERVER_RANDOM_INDEX: usize = TLS_HEADER_SIZE + 1 + 3 + 2;
const SESSION_ID_LENGTH_INDEX: usize = SERVER_RANDOM_INDEX + TLS_RANDOM_SIZE;
const CLIENT_HELLO_MIN_LEN: usize = SESSION_ID_LENGTH_INDEX + 1 + TLS_SESSION_ID_SIZE;
const CLIENT_HELLO_HMAC_INDEX: usize =
    SESSION_ID_LENGTH_INDEX + 1 + TLS_SESSION_ID_SIZE - HMAC_SIZE;
const MAX_WRITE_RECORD: usize = 16_384;
const TLS_RECORD_APPLICATION_DATA: u8 = 23;
const TLS_RECORD_ALERT: u8 = 21;
const TLS_RECORD_HANDSHAKE: u8 = 22;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 1;
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 2;

struct User {
    name: String,
    password: Vec<u8>,
    key: Key,
}

/// v3 wildcard SNI 模式。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WildcardSni {
    Off,
    /// 仅认证成功时使用 SNI:443 作为伪装目标。
    Authed,
    /// 认证成功与未认证回落都使用 SNI:443。
    All,
}

/// 与监听器生命周期绑定的不可变认证与伪装目标状态。
pub(crate) struct Prepared {
    tag: String,
    users: Vec<User>,
    handshake: Target,
    handshake_for_server_name: HashMap<String, Target>,
    strict_mode: bool,
    wildcard_sni: WildcardSni,
}

impl Prepared {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        tag: String,
        users: &[crate::config::User],
        handshake: Target,
        handshake_for_server_name: Vec<(String, Target)>,
        strict_mode: bool,
        wildcard_sni: WildcardSni,
    ) -> io::Result<Self> {
        if users.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ShadowTLS 用户不得为空",
            ));
        }
        Ok(Self {
            tag,
            users: users
                .iter()
                .map(|user| User {
                    name: user.name.clone(),
                    password: user.password.as_bytes().to_vec(),
                    key: Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, user.password.as_bytes()),
                })
                .collect(),
            handshake,
            handshake_for_server_name: handshake_for_server_name.into_iter().collect(),
            strict_mode,
            wildcard_sni,
        })
    }
}

/// 认证成功后交给 detour 的明文流；记录层仍由本类型维护。
pub(crate) struct Verified<S> {
    inner: S,
    read_hmac: HmacContext,
    write_hmac: HmacContext,
    buffer: Vec<u8>,
    offset: usize,
    header: [u8; TLS_HEADER_SIZE],
    header_filled: usize,
    payload: Vec<u8>,
    payload_filled: usize,
    pending: Vec<u8>,
    pending_offset: usize,
    pending_len: usize,
}

impl<S> Verified<S> {
    fn new(inner: S, read_hmac: HmacContext, write_hmac: HmacContext, first: Vec<u8>) -> Self {
        Self {
            inner,
            read_hmac,
            write_hmac,
            buffer: first,
            offset: 0,
            header: [0; TLS_HEADER_SIZE],
            header_filled: 0,
            payload: Vec::new(),
            payload_filled: 0,
            pending: Vec::new(),
            pending_offset: 0,
            pending_len: 0,
        }
    }

    fn reset_record(&mut self) {
        self.header_filled = 0;
        self.payload_filled = 0;
    }
}

impl<S: DetourStream> DetourStream for Verified<S> {
    fn abort_linger(&self) {
        self.inner.abort_linger();
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Verified<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.offset < this.buffer.len() {
            let count = buf.remaining().min(this.buffer.len() - this.offset);
            buf.put_slice(&this.buffer[this.offset..this.offset + count]);
            this.offset += count;
            return Poll::Ready(Ok(()));
        }
        this.buffer.clear();
        this.offset = 0;
        while this.header_filled < TLS_HEADER_SIZE {
            let mut read = ReadBuf::new(&mut this.header[this.header_filled..]);
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            let count = read.filled().len();
            if count == 0 {
                return Poll::Ready(if this.header_filled == 0 {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ShadowTLS 记录头截断",
                    ))
                });
            }
            this.header_filled += count;
        }
        let length = usize::from(u16::from_be_bytes([this.header[3], this.header[4]]));
        if this.header[0] == TLS_RECORD_ALERT {
            this.reset_record();
            send_alert(&mut this.inner, cx);
            return Poll::Ready(Ok(()));
        }
        if this.header[0] != TLS_RECORD_APPLICATION_DATA
            || this.header[1] != 3
            || this.header[2] != 3
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowTLS 记录类型无效",
            )));
        }
        if length < HMAC_SIZE {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowTLS 记录长度无效",
            )));
        }
        if this.payload.len() != length {
            this.payload.resize(length, 0);
        }
        this.payload_filled = 0;
        while this.payload_filled < length {
            let mut read = ReadBuf::new(&mut this.payload[this.payload_filled..]);
            std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            let count = read.filled().len();
            if count == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ShadowTLS 记录截断",
                )));
            }
            this.payload_filled += count;
        }
        let mut check = this.read_hmac.clone();
        check.update(&this.payload[HMAC_SIZE..]);
        let tag = check.sign();
        if !constant_time_eq(&tag.as_ref()[..HMAC_SIZE], &this.payload[..HMAC_SIZE]) {
            send_alert(&mut this.inner, cx);
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ShadowTLS 记录校验失败",
            )));
        }
        let mac = [
            this.payload[0],
            this.payload[1],
            this.payload[2],
            this.payload[3],
        ];
        this.read_hmac.update(&this.payload[HMAC_SIZE..]);
        this.read_hmac.update(&mac);
        this.buffer.clear();
        this.buffer.extend_from_slice(&this.payload[HMAC_SIZE..]);
        this.reset_record();
        let count = buf.remaining().min(this.buffer.len());
        buf.put_slice(&this.buffer[..count]);
        this.offset = count;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Verified<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.pending.is_empty() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let count = buf.len().min(MAX_WRITE_RECORD);
            let data = &buf[..count];
            this.write_hmac.update(data);
            let tag = this.write_hmac.clone().sign();
            let mac = [
                tag.as_ref()[0],
                tag.as_ref()[1],
                tag.as_ref()[2],
                tag.as_ref()[3],
            ];
            this.write_hmac.update(&mac);
            this.pending.clear();
            this.pending.reserve(TLS_HMAC_HEADER_SIZE + count);
            this.pending.push(TLS_RECORD_APPLICATION_DATA);
            this.pending.extend_from_slice(&[3, 3]);
            let length = u16::try_from(count + HMAC_SIZE).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "ShadowTLS 记录长度溢出")
            })?;
            this.pending.extend_from_slice(&length.to_be_bytes());
            this.pending.extend_from_slice(&mac);
            this.pending.extend_from_slice(data);
            this.pending_offset = 0;
            this.pending_len = count;
        }
        while this.pending_offset < this.pending.len() {
            let written = std::task::ready!(
                Pin::new(&mut this.inner).poll_write(cx, &this.pending[this.pending_offset..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "ShadowTLS 记录写入失败",
                )));
            }
            this.pending_offset += written;
        }
        this.pending.clear();
        this.pending_offset = 0;
        let count = this.pending_len;
        this.pending_len = 0;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while this.pending_offset < this.pending.len() {
            let written = std::task::ready!(
                Pin::new(&mut this.inner).poll_write(cx, &this.pending[this.pending_offset..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "ShadowTLS 记录写入失败",
                )));
            }
            this.pending_offset += written;
        }
        this.pending.clear();
        this.pending_offset = 0;
        this.pending_len = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// ShadowTLS 握手结果。
#[allow(clippy::large_enum_variant)] // 握手期构造一次，随后立即消费。
pub(crate) enum AuthOutcome<S> {
    /// 认证成功；握手许可继续交给内层协议，覆盖其认证阶段。
    Authenticated {
        stream: Verified<S>,
        permit: crate::runtime::HandshakePermits,
    },
    /// 未认证流量已按真实 TLS 回落到伪装服务器。
    Fallback,
}

/// 完成 ShadowTLS v3 握手。
///
/// 回落连接可能长期存活，因此在进入双向复制前释放握手许可，避免伪装流量
/// 占满 `max_handshakes`。
pub(crate) async fn accept<S: DetourStream>(
    stream: S,
    prepared: Arc<Prepared>,
    ctx: Arc<forward::Context>,
    permit: crate::runtime::HandshakePermits,
) -> io::Result<AuthOutcome<S>> {
    let deadline = Duration::from_millis(ctx.limits.handshake_timeout_ms);
    let mut stream = stream;
    let client_hello = timeout(deadline, read_record(&mut stream))
        .await
        .map_err(|_| handshake_timeout("ShadowTLS 客户端问候超时"))??;
    let server_name = client_server_name(&client_hello);
    let Some(user_index) = verify_client_hello(&client_hello, &prepared.users) else {
        drop(permit);
        let target = handshake_target(&prepared, server_name.as_deref(), false);
        fallback(stream, &prepared.tag, &ctx, &client_hello, &target).await?;
        return Ok(AuthOutcome::Fallback);
    };
    let user = &prepared.users[user_index];
    let target = handshake_target(&prepared, server_name.as_deref(), true);
    let mut server = ctx.connect(&prepared.tag, &target).await?;
    let server_hello = timeout(deadline, async {
        server.write_all(&client_hello).await?;
        let server_hello = read_record(&mut server).await?;
        stream.write_all(&server_hello).await?;
        Ok::<Vec<u8>, io::Error>(server_hello)
    })
    .await
    .map_err(|_| handshake_timeout("ShadowTLS 服务端问候超时"))??;
    let Some(server_random) = extract_server_random(&server_hello) else {
        // 与上游一致：无法提取 server_random 时退化为透明双向复制。
        drop(permit);
        tokio::io::copy_bidirectional(&mut stream, &mut server).await?;
        return Ok(AuthOutcome::Fallback);
    };
    if prepared.strict_mode && !server_hello_supports_tls13(&server_hello) {
        drop(permit);
        tokio::io::copy_bidirectional(&mut stream, &mut server).await?;
        return Ok(AuthOutcome::Fallback);
    }
    let kdf_key = kdf(&user.password, &server_random);
    let mut verify_seed = HmacContext::with_key(&user.key);
    verify_seed.update(&server_random);
    verify_seed.update(b"C");
    // 握手期写链只以 server_random 起链且不追加 MAC；认证完成后的写链另起
    // `server_random || "S"`，不能复用被握手记录推进过的上下文。
    let mut relay_write = HmacContext::with_key(&user.key);
    relay_write.update(&server_random);
    let (read_state, first) = timeout(
        deadline,
        relay_handshake(
            &mut stream,
            &mut server,
            &verify_seed,
            relay_write,
            &kdf_key,
        ),
    )
    .await
    .map_err(|_| handshake_timeout("ShadowTLS 握手中转超时"))??;
    let mut write_state = HmacContext::with_key(&user.key);
    write_state.update(&server_random);
    write_state.update(b"S");
    drop(server);
    tracing::debug!(
        event = "shadowtls_authenticated",
        inbound = %prepared.tag,
        user = %user.name
    );
    Ok(AuthOutcome::Authenticated {
        stream: Verified::new(stream, read_state, write_state, first),
        permit,
    })
}

enum RelayEvent {
    Client(Vec<u8>),
    Server(Vec<u8>),
}

/// 认证后的中转：客户端首个合法记录之前的服务器记录需 XOR 并补 HMAC。
async fn relay_handshake<S, T>(
    client: &mut S,
    server: &mut T,
    verify_seed: &HmacContext,
    mut write_state: HmacContext,
    kdf_key: &[u8; 32],
) -> io::Result<(HmacContext, Vec<u8>)>
where
    S: DetourStream,
    T: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let event = tokio::select! {
            result = read_record(client) => RelayEvent::Client(result?),
            result = read_record(server) => RelayEvent::Server(result?),
        };
        match event {
            RelayEvent::Client(frame) => {
                if frame.len() > TLS_HMAC_HEADER_SIZE && frame[0] == TLS_RECORD_APPLICATION_DATA {
                    let payload = &frame[TLS_HMAC_HEADER_SIZE..];
                    let mut check = verify_seed.clone();
                    check.update(payload);
                    let tag = check.sign();
                    if constant_time_eq(
                        &tag.as_ref()[..HMAC_SIZE],
                        &frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE],
                    ) {
                        let mut state = verify_seed.clone();
                        state.update(payload);
                        state.update(&tag.as_ref()[..HMAC_SIZE]);
                        return Ok((state, payload.to_vec()));
                    }
                }
                server.write_all(&frame).await?;
            }
            RelayEvent::Server(frame) => {
                if frame[0] == TLS_RECORD_APPLICATION_DATA {
                    if frame.len() <= TLS_HEADER_SIZE {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "ShadowTLS 服务端记录长度无效",
                        ));
                    }
                    let mut payload = frame[TLS_HEADER_SIZE..].to_vec();
                    xor(&mut payload, kdf_key);
                    write_state.update(&payload);
                    let tag = write_state.clone().sign();
                    let mut output = Vec::with_capacity(TLS_HMAC_HEADER_SIZE + payload.len());
                    output.push(TLS_RECORD_APPLICATION_DATA);
                    output.extend_from_slice(&[3, 3]);
                    let length = u16::try_from(payload.len() + HMAC_SIZE)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "记录过长"))?;
                    output.extend_from_slice(&length.to_be_bytes());
                    output.extend_from_slice(&tag.as_ref()[..HMAC_SIZE]);
                    output.extend_from_slice(&payload);
                    client.write_all(&output).await?;
                } else {
                    client.write_all(&frame).await?;
                }
            }
        }
    }
}

async fn fallback<S: DetourStream>(
    client: S,
    tag: &str,
    ctx: &forward::Context,
    client_hello: &[u8],
    target: &Target,
) -> io::Result<()> {
    let mut server = ctx.connect(tag, target).await?;
    server.write_all(client_hello).await?;
    // 与普通中继一致：长时间无数据流动的连接不应永久占用名额。
    forward::copy_with_idle(client, server, ctx.stats.idle_timeout()).await?;
    Ok(())
}

/// 读取一条完整 TLS 记录；长度字段为 u16，单条记录上界 65540 字节。
async fn read_record<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut header = [0u8; TLS_HEADER_SIZE];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut frame = vec![0u8; TLS_HEADER_SIZE + length];
    frame[..TLS_HEADER_SIZE].copy_from_slice(&header);
    stream.read_exact(&mut frame[TLS_HEADER_SIZE..]).await?;
    Ok(frame)
}

/// 选择伪装握手目标。
///
/// SNI 精确映射优先；否则按 wildcard 模式：`authed` 只在认证成功时使用
/// `SNI:443`，`all` 在回落时也使用，`off` 始终使用默认目标。
fn handshake_target(prepared: &Prepared, server_name: Option<&str>, authenticated: bool) -> Target {
    if let Some(target) = server_name
        .and_then(|name| prepared.handshake_for_server_name.get(name))
        .cloned()
    {
        return target;
    }
    let wildcard = server_name.map(|name| Target {
        host: crate::session::Host::Domain(name.to_owned()),
        port: 443,
    });
    match (prepared.wildcard_sni, authenticated) {
        (WildcardSni::All, _) | (WildcardSni::Authed, true) => {
            wildcard.unwrap_or_else(|| prepared.handshake.clone())
        }
        _ => prepared.handshake.clone(),
    }
}

/// 从首个 ClientHello 记录提取 SNI；缺失或不合法时返回 `None`。
fn client_server_name(frame: &[u8]) -> Option<String> {
    match crate::transport::sniff::tls_server_name(frame) {
        crate::transport::sniff::Sniffed::Domain(name) => Some(name),
        _ => None,
    }
}

fn verify_client_hello(frame: &[u8], users: &[User]) -> Option<usize> {
    if frame.len() < CLIENT_HELLO_MIN_LEN
        || frame[0] != TLS_RECORD_HANDSHAKE
        || frame[5] != TLS_HANDSHAKE_CLIENT_HELLO
        || frame[SESSION_ID_LENGTH_INDEX] != TLS_SESSION_ID_SIZE as u8
    {
        return None;
    }
    users.iter().position(|user| {
        let mut context = HmacContext::with_key(&user.key);
        context.update(&frame[TLS_HEADER_SIZE..CLIENT_HELLO_HMAC_INDEX]);
        context.update(&[0, 0, 0, 0]);
        context.update(&frame[CLIENT_HELLO_HMAC_INDEX + HMAC_SIZE..]);
        let tag = context.sign();
        constant_time_eq(
            &tag.as_ref()[..HMAC_SIZE],
            &frame[CLIENT_HELLO_HMAC_INDEX..CLIENT_HELLO_HMAC_INDEX + HMAC_SIZE],
        )
    })
}

fn extract_server_random(frame: &[u8]) -> Option<[u8; TLS_RANDOM_SIZE]> {
    if frame.len() < SERVER_RANDOM_INDEX + TLS_RANDOM_SIZE
        || frame[0] != TLS_RECORD_HANDSHAKE
        || frame[5] != TLS_HANDSHAKE_SERVER_HELLO
    {
        return None;
    }
    let mut random = [0u8; TLS_RANDOM_SIZE];
    random.copy_from_slice(&frame[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + TLS_RANDOM_SIZE]);
    Some(random)
}

/// 查找 ServerHello 是否声明 TLS 1.3（supported_versions 扩展值 0x0304）。
fn server_hello_supports_tls13(frame: &[u8]) -> bool {
    let mut rest = match frame.get(SESSION_ID_LENGTH_INDEX..) {
        Some(rest) => rest,
        None => return false,
    };
    let Some((&session_id_len, tail)) = rest.split_first() else {
        return false;
    };
    rest = tail;
    let skip = usize::from(session_id_len) + 3;
    if rest.len() < skip + 2 {
        return false;
    }
    rest = &rest[skip..];
    let extensions_len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
    rest = &rest[2..];
    let end = rest.len().min(extensions_len);
    let mut rest = &rest[..end];
    while rest.len() >= 4 {
        let kind = u16::from_be_bytes([rest[0], rest[1]]);
        let length = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        rest = &rest[4..];
        if rest.len() < length {
            return false;
        }
        if kind == 43 {
            return length == 2 && rest[0] == 0x03 && rest[1] == 0x04;
        }
        rest = &rest[length..];
    }
    false
}

fn kdf(password: &[u8], server_random: &[u8; TLS_RANDOM_SIZE]) -> [u8; 32] {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(password);
    context.update(server_random);
    let value = context.finish();
    let mut output = [0u8; 32];
    output.copy_from_slice(value.as_ref());
    output
}

fn xor(data: &mut [u8], key: &[u8; 32]) {
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn send_alert<S: AsyncWrite + Unpin>(stream: &mut S, cx: &mut TaskContext<'_>) {
    let mut record = [0u8; 31];
    record[0] = TLS_RECORD_ALERT;
    record[1] = 3;
    record[2] = 3;
    record[3] = 0;
    record[4] = 26;
    if rand::fill(&mut record[TLS_HEADER_SIZE..]).is_err() {
        return;
    }
    // 尽力发送；写端暂时不可写时不再排队，避免在读取路径上持有额外状态。
    let _ = Pin::new(stream).poll_write(cx, &record);
}

fn handshake_timeout(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    impl DetourStream for tokio::io::DuplexStream {}

    fn user(name: &str, password: &str) -> User {
        User {
            name: name.to_owned(),
            password: password.as_bytes().to_vec(),
            key: Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, password.as_bytes()),
        }
    }

    fn build_client_hello(password: &str) -> Vec<u8> {
        // ClientHello 记录：5 字节记录头 + 1 字节握手类型 + 3 字节长度
        // + 2 字节版本 + 32 字节随机 + session_id 长度与 32 字节内容。
        let mut frame = vec![0u8; CLIENT_HELLO_MIN_LEN + 4];
        frame[0] = TLS_RECORD_HANDSHAKE;
        frame[1] = 3;
        frame[2] = 1;
        let body = u16::try_from(frame.len() - TLS_HEADER_SIZE).unwrap();
        frame[3..5].copy_from_slice(&body.to_be_bytes());
        frame[5] = TLS_HANDSHAKE_CLIENT_HELLO;
        let handshake_len = u16::try_from(frame.len() - 9).unwrap().to_be_bytes();
        frame[6] = 0;
        frame[7] = handshake_len[0];
        frame[8] = handshake_len[1];
        frame[9] = 3;
        frame[10] = 3;
        frame[SESSION_ID_LENGTH_INDEX] = TLS_SESSION_ID_SIZE as u8;
        let mut context = HmacContext::with_key(&Key::new(
            HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            password.as_bytes(),
        ));
        context.update(&frame[TLS_HEADER_SIZE..CLIENT_HELLO_HMAC_INDEX]);
        context.update(&[0, 0, 0, 0]);
        context.update(&frame[CLIENT_HELLO_HMAC_INDEX + HMAC_SIZE..]);
        let tag = context.sign();
        frame[CLIENT_HELLO_HMAC_INDEX..CLIENT_HELLO_HMAC_INDEX + HMAC_SIZE]
            .copy_from_slice(&tag.as_ref()[..HMAC_SIZE]);
        frame
    }

    fn build_server_hello(random: [u8; TLS_RANDOM_SIZE], version: Option<u16>) -> Vec<u8> {
        // TLS 1.2 外观的 ServerHello：无 session_id、单套件、单压缩方法。
        let mut frame = vec![0u8; SESSION_ID_LENGTH_INDEX + 1 + 3];
        frame[0] = TLS_RECORD_HANDSHAKE;
        frame[1] = 3;
        frame[2] = 3;
        frame[5] = TLS_HANDSHAKE_SERVER_HELLO;
        frame[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + TLS_RANDOM_SIZE].copy_from_slice(&random);
        frame[SESSION_ID_LENGTH_INDEX] = 0;
        let extension_len = if version.is_some() { 6u16 } else { 0 };
        frame.extend_from_slice(&extension_len.to_be_bytes());
        if let Some(version) = version {
            frame.extend_from_slice(&43u16.to_be_bytes());
            frame.extend_from_slice(&2u16.to_be_bytes());
            frame.extend_from_slice(&version.to_be_bytes());
        }
        let body = u16::try_from(frame.len() - TLS_HEADER_SIZE).unwrap();
        frame[3..5].copy_from_slice(&body.to_be_bytes());
        frame
    }

    fn prepared_for(wildcard: WildcardSni, mapping: &[(&str, &str, u16)]) -> Prepared {
        Prepared {
            tag: "shadowtls".into(),
            users: vec![user("alice", "secret")],
            handshake: Target {
                host: crate::session::Host::Domain("default.test".into()),
                port: 443,
            },
            handshake_for_server_name: mapping
                .iter()
                .map(|(name, host, port)| {
                    (
                        (*name).to_owned(),
                        Target {
                            host: crate::session::Host::Domain((*host).to_owned()),
                            port: *port,
                        },
                    )
                })
                .collect(),
            strict_mode: true,
            wildcard_sni: wildcard,
        }
    }

    #[test]
    fn handshake_target_prefers_mapping_then_wildcard_mode() {
        let default = Target {
            host: crate::session::Host::Domain("default.test".into()),
            port: 443,
        };
        let off = prepared_for(
            WildcardSni::Off,
            &[("mapped.test", "mapped.internal", 8443)],
        );
        assert_eq!(handshake_target(&off, None, true), default);
        assert_eq!(handshake_target(&off, Some("other.test"), true), default);
        assert_eq!(
            handshake_target(&off, Some("mapped.test"), false),
            Target {
                host: crate::session::Host::Domain("mapped.internal".into()),
                port: 8443
            }
        );

        let authed = prepared_for(WildcardSni::Authed, &[]);
        assert_eq!(
            handshake_target(&authed, Some("sni.test"), true),
            Target {
                host: crate::session::Host::Domain("sni.test".into()),
                port: 443
            }
        );
        assert_eq!(handshake_target(&authed, Some("sni.test"), false), default);
        assert_eq!(handshake_target(&authed, None, true), default);

        let all = prepared_for(WildcardSni::All, &[]);
        for authenticated in [false, true] {
            assert_eq!(
                handshake_target(&all, Some("sni.test"), authenticated),
                Target {
                    host: crate::session::Host::Domain("sni.test".into()),
                    port: 443
                }
            );
        }
        assert_eq!(handshake_target(&all, None, true), default);
    }

    #[test]
    fn client_hello_hmac_matches_only_the_configured_password() {
        let users = vec![user("alice", "secret"), user("bob", "other-secret")];
        assert_eq!(
            verify_client_hello(&build_client_hello("secret"), &users),
            Some(0)
        );
        assert_eq!(
            verify_client_hello(&build_client_hello("other-secret"), &users),
            Some(1)
        );
        assert_eq!(
            verify_client_hello(&build_client_hello("unknown"), &users),
            None
        );
        // 破坏 session_id 末 4 字节后必须拒绝。
        let mut frame = build_client_hello("secret");
        frame[CLIENT_HELLO_HMAC_INDEX] ^= 0xff;
        assert_eq!(verify_client_hello(&frame, &users), None);
    }

    #[test]
    fn server_hello_extracts_random_and_detects_tls13() {
        let random = [9u8; TLS_RANDOM_SIZE];
        let frame = build_server_hello(random, Some(0x0304));
        assert_eq!(extract_server_random(&frame), Some(random));
        assert!(server_hello_supports_tls13(&frame));

        let old = build_server_hello([1u8; TLS_RANDOM_SIZE], None);
        assert_eq!(extract_server_random(&old), Some([1u8; TLS_RANDOM_SIZE]));
        assert!(!server_hello_supports_tls13(&old));
        assert!(!server_hello_supports_tls13(&[0u8; 10]));
    }

    #[tokio::test]
    async fn verified_stream_reads_and_writes_authenticated_records() {
        let (mut peer, server) = duplex(4096);
        let password = b"shadowtls-test-password";
        let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, password);
        let server_random = b"0123456789abcdef0123456789abcdef";

        let mut read_state = HmacContext::with_key(&key);
        read_state.update(server_random);
        read_state.update(b"C");
        let mut write_state = HmacContext::with_key(&key);
        write_state.update(server_random);
        write_state.update(b"S");

        // 模拟握手期已消费的首个合法客户端记录。
        let mut first_state = read_state.clone();
        first_state.update(b"first");
        let first_tag = first_state.clone().sign();
        read_state.update(b"first");
        read_state.update(&first_tag.as_ref()[..HMAC_SIZE]);
        let mut verified = Verified::new(server, read_state, write_state, b"first".to_vec());

        let mut first = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut verified, &mut first)
            .await
            .unwrap();
        assert_eq!(&first, b"first");

        // 客户端方向的下一记录沿用同一 HMAC 链。
        let mut peer_state = HmacContext::with_key(&key);
        peer_state.update(server_random);
        peer_state.update(b"C");
        peer_state.update(b"first");
        peer_state.update(&first_tag.as_ref()[..HMAC_SIZE]);
        let payload = b"second";
        let mut check = peer_state.clone();
        check.update(payload);
        let tag = check.sign();
        let mut record = vec![TLS_RECORD_APPLICATION_DATA, 3, 3];
        record.extend_from_slice(
            &u16::try_from(payload.len() + HMAC_SIZE)
                .unwrap()
                .to_be_bytes(),
        );
        record.extend_from_slice(&tag.as_ref()[..HMAC_SIZE]);
        record.extend_from_slice(payload);
        peer.write_all(&record).await.unwrap();

        let mut second = [0u8; 6];
        tokio::io::AsyncReadExt::read_exact(&mut verified, &mut second)
            .await
            .unwrap();
        assert_eq!(&second, b"second");

        // 服务端写方向独立链：先 payload 再补自身前 4 字节 HMAC。
        verified.write_all(b"reply").await.unwrap();
        let mut written = vec![0u8; TLS_HMAC_HEADER_SIZE + 5];
        peer.read_exact(&mut written).await.unwrap();
        assert_eq!(
            &written[..5],
            &[TLS_RECORD_APPLICATION_DATA, 3, 3, 0, 9][..]
        );
        let mut expected = HmacContext::with_key(&key);
        expected.update(server_random);
        expected.update(b"S");
        expected.update(b"reply");
        let expected_tag = expected.sign();
        assert_eq!(&written[5..9], &expected_tag.as_ref()[..HMAC_SIZE]);
        assert_eq!(&written[9..], b"reply");
    }

    #[tokio::test]
    async fn verified_stream_rejects_tampered_records() {
        let (mut peer, server) = duplex(4096);
        let key = Key::new(HMAC_SHA1_FOR_LEGACY_USE_ONLY, b"pw");
        let mut read_state = HmacContext::with_key(&key);
        read_state.update(b"sr");
        read_state.update(b"C");
        let mut write_state = HmacContext::with_key(&key);
        write_state.update(b"sr");
        write_state.update(b"S");
        let mut verified = Verified::new(server, read_state, write_state, Vec::new());

        let mut record = vec![TLS_RECORD_APPLICATION_DATA, 3, 3];
        record.extend_from_slice(&4u16.to_be_bytes());
        record.extend_from_slice(&[0, 0, 0, 0]);
        peer.write_all(&record).await.unwrap();
        let mut buf = [0u8; 1];
        let error = tokio::io::AsyncReadExt::read_exact(&mut verified, &mut buf)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
