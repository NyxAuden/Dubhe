use std::{
    collections::HashSet,
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::util::fnv1a;
use crate::{
    config::{VmessUser, parse_uuid},
    session::{Host, Target},
};

use super::{crypto, replay::ReplayPool};

const MAX_HEADER: usize = 316;
const MIN_HEADER: usize = 42; // cmd3: 固定前缀38 + FNV4，没有目标。
const PACKET_ADDR: &str = "sp.packet-addr.v2fly.arpa";
const MASK: u8 = 0x04;
const PADDING: u8 = 0x08;
const AUTH_LENGTH: u8 = 0x10;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Policy {
    pub xudp: bool,
    pub packetaddr: bool,
    pub allow_insecure_body: bool,
    pub allow_authenticated_length: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Tcp(Target),
    Udp(Target),
    /// 命令 3：完整 Mux；UDP 帧由运行层按 xudp 策略门控。
    Mux,
    PacketAddr,
}

struct User {
    name: String,
    uuid: [u8; 16],
    command_key: [u8; 16],
    auth_key: [u8; 16],
}

pub(crate) struct Prepared {
    users: Vec<User>,
    replay: Arc<ReplayPool>,
    policy: Policy,
}

impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("users", &self.users.len())
            .field("credentials", &"[REDACTED]")
            .field("policy", &self.policy)
            .finish()
    }
}

pub(crate) struct Accepted {
    pub mode: Mode,
    pub user: String,
    pub security: u8,
    pub options: u8,
    pub key: [u8; 16],
    pub iv: [u8; 16],
    response: [u8; 38],
    response_offset: usize,
    replied: bool,
    reply_failed: bool,
}

impl fmt::Debug for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .field("mode", &self.mode)
            .field("user", &self.user)
            .field("security", &self.security)
            .field("options", &self.options)
            .field("key", &"[REDACTED]")
            .field("iv", &"[REDACTED]")
            .field("response", &"[REDACTED]")
            .field("replied", &self.replied)
            .finish()
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "VMess 认证失败")
}

impl Prepared {
    pub(crate) fn new(
        users: &[VmessUser],
        replay: Arc<ReplayPool>,
        policy: Policy,
    ) -> io::Result<Self> {
        let bad_config = || io::Error::new(io::ErrorKind::InvalidInput, "VMess 用户配置无效");
        if !(1..=1024).contains(&users.len()) {
            return Err(bad_config());
        }
        let mut names = HashSet::new();
        let mut identities = HashSet::new();
        let mut prepared = Vec::with_capacity(users.len());
        for user in users {
            let uuid = parse_uuid(&user.uuid).ok_or_else(bad_config)?;
            if user.name.is_empty() || !names.insert(&user.name) || !identities.insert(uuid) {
                return Err(bad_config());
            }
            let command_key = crypto::command_key(&uuid);
            let auth_key = crypto::kdf16(&command_key, &[b"AES Auth ID Encryption"]);
            prepared.push(User {
                name: user.name.clone(),
                uuid,
                command_key,
                auth_key,
            });
        }
        Ok(Self {
            users: prepared,
            replay,
            policy,
        })
    }

    /// 入站是否允许 Mux 内的 UDP 会话；命令 3 的 TCP 会话不受该开关限制。
    pub(crate) fn allow_udp(&self) -> bool {
        self.policy.xudp
    }

    /// tls 必须由已完成的承载 TLS 握手提供。这里只读有限认证头，不执行目标 IO。
    /// 取消后必须关闭该承载，不能在已消费的半头上重新开始握手。
    pub(crate) async fn handshake<S: AsyncRead + Unpin>(
        &self,
        io: &mut S,
        tls: bool,
    ) -> io::Result<Accepted> {
        let mut id = [0; 16];
        io.read_exact(&mut id).await?;
        let now = self.replay.now()?;
        let (user, timestamp) = self.identify(&id, now)?;
        // 成功识别身份和AuthID即提交；后续失败/取消不撤销此保护项。
        self.replay.auth(user.uuid, id, timestamp, now)?;
        let mut encrypted_length = [0; 18];
        io.read_exact(&mut encrypted_length).await?;
        let mut nonce = [0; 8];
        io.read_exact(&mut nonce).await?;
        let length = open_request(&user.command_key, &id, &nonce, true, &encrypted_length)?;
        let length: [u8; 2] = length.try_into().map_err(|_| invalid("VMess 头长度无效"))?;
        let length = usize::from(u16::from_be_bytes(length));
        if !(MIN_HEADER..=MAX_HEADER).contains(&length) {
            return Err(invalid("VMess 头长度超出范围"));
        }
        // 先认证并限制长度，再读取固定上界缓冲，绝不按peer任意u16分配。
        let mut encrypted = [0; MAX_HEADER + 16];
        io.read_exact(&mut encrypted[..length + 16]).await?;
        let header = open_request(
            &user.command_key,
            &id,
            &nonce,
            false,
            &encrypted[..length + 16],
        )?;
        let mut accepted = parse_header(&header, self.policy, tls)?;
        self.replay.session(user.uuid, accepted.key, accepted.iv)?;
        accepted.user.clone_from(&user.name);
        Ok(accepted)
    }

    fn identify(&self, id: &[u8; 16], now: u64) -> io::Result<(&User, u64)> {
        let mut selected = None;
        let mut matches = 0usize;
        // 扫描全部候选，CRC与时间只用于早期识别，不代表完整请求已经认证。
        for user in &self.users {
            let plain = crypto::auth_id(&user.auth_key, id, false);
            let timestamp = u64::from_be_bytes(plain[..8].try_into().expect("固定长度"));
            let crc = u32::from_be_bytes(plain[12..].try_into().expect("固定长度"));
            if crc32fast::hash(&plain[..12]) == crc
                && timestamp <= i64::MAX as u64
                && timestamp.abs_diff(now) <= 120
            {
                matches += 1;
                selected = Some((user, timestamp));
            }
        }
        if matches != 1 {
            return Err(denied());
        }
        selected.ok_or_else(denied)
    }
}

fn open_request(
    key: &[u8; 16],
    id: &[u8; 16],
    connection_nonce: &[u8; 8],
    length: bool,
    encrypted: &[u8],
) -> io::Result<Vec<u8>> {
    let (key_label, nonce_label): (&[u8], &[u8]) = if length {
        (
            b"VMess Header AEAD Key_Length",
            b"VMess Header AEAD Nonce_Length",
        )
    } else {
        (b"VMess Header AEAD Key", b"VMess Header AEAD Nonce")
    };
    let nonce: [u8; 12] = crypto::kdf(key, &[nonce_label, id, connection_nonce])[..12]
        .try_into()
        .expect("固定长度");
    let key = crypto::kdf16(key, &[key_label, id, connection_nonce]);
    crypto::Cipher::new(3, &key)?.open(&nonce, id, encrypted)
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parse_header(header: &[u8], tls: bool) {
    let _ = parse_header(header, Policy::default(), tls);
}

fn parse_header(header: &[u8], policy: Policy, tls: bool) -> io::Result<Accepted> {
    if !(MIN_HEADER..=MAX_HEADER).contains(&header.len()) {
        return Err(invalid("VMess 内层头长度无效"));
    }
    let content_end = header.len() - 4;
    let supplied = u32::from_be_bytes(header[content_end..].try_into().expect("已检查长度"));
    if fnv1a(&header[..content_end]) != supplied || header[0] != 1 || header[36] != 0 {
        return Err(invalid("VMess 内层头校验失败"));
    }
    let iv = header[1..17].try_into().expect("已检查长度");
    let key = header[17..33].try_into().expect("已检查长度");
    let response_auth = header[33];
    let options = header[34];
    let security = header[35] & 0x0f;
    let padding = usize::from(header[35] >> 4);
    let command = header[37];
    let address_end = content_end
        .checked_sub(padding)
        .ok_or_else(|| invalid("VMess padding无效"))?;
    if address_end < 38 {
        return Err(invalid("VMess padding无效"));
    }
    let mode = match command {
        1 | 2 => {
            let target = parse_target(&header[38..address_end])?;
            if matches!(&target.host, Host::Domain(domain) if domain == PACKET_ADDR) {
                if command != 2 || !policy.packetaddr {
                    return Err(invalid("VMess packetaddr未开启或命令无效"));
                }
                Mode::PacketAddr
            } else {
                // UoT 的服务端发现请求固定使用魔数域名且端口为 0，
                // 见 sing-box `RequestDestination`；其余目标仍拒绝端口 0。
                if target.port == 0 && crate::udp::uot_version(&target).is_none() {
                    return Err(invalid("VMess 目标端口无效"));
                }
                if command == 1 {
                    Mode::Tcp(target)
                } else {
                    Mode::Udp(target)
                }
            }
        }
        // 命令 3 固定无目标；xudp 只门控 Mux 内的 UDP 会话。
        3 if address_end == 38 => Mode::Mux,
        _ => return Err(invalid("VMess 命令或目标无效")),
    };
    validate_options(security, options, command, policy, tls)?;
    let response = make_response(&key, &iv, response_auth)?;
    Ok(Accepted {
        mode,
        user: String::new(),
        security,
        options,
        key,
        iv,
        response,
        response_offset: 0,
        replied: false,
        reply_failed: false,
    })
}

fn validate_options(
    security: u8,
    options: u8,
    command: u8,
    policy: Policy,
    tls: bool,
) -> io::Result<()> {
    if options & !0x1d != 0 || options & PADDING != 0 && options & MASK == 0 {
        return Err(invalid("VMess 选项组合不受支持"));
    }
    match security {
        3 | 4 if options & AUTH_LENGTH == 0 || policy.allow_authenticated_length => Ok(()),
        5 if (tls || policy.allow_insecure_body)
            && (options == 1 || options == 0 && command != 2) =>
        {
            Ok(())
        }
        _ => Err(invalid("VMess 安全类型或策略不允许")),
    }
}

fn parse_target(bytes: &[u8]) -> io::Result<Target> {
    if bytes.len() < 3 {
        return Err(invalid("VMess 目标截断"));
    }
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let host = match bytes[2] {
        1 if bytes.len() == 7 => {
            Host::Ip(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[3..]).expect("已检查长度")).into())
        }
        3 if bytes.len() == 19 => {
            Host::Ip(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[3..]).expect("已检查长度")).into())
        }
        2 if bytes.len() >= 4 && bytes[3] != 0 && bytes.len() == 4 + usize::from(bytes[3]) => {
            let domain = &bytes[4..];
            if !domain.iter().all(u8::is_ascii_graphic) {
                return Err(invalid("VMess 目标域名无效"));
            }
            Host::Domain(
                std::str::from_utf8(domain)
                    .map_err(|_| invalid("VMess 目标域名无效"))?
                    .to_owned(),
            )
        }
        _ => return Err(invalid("VMess 地址类型或长度无效")),
    };
    Ok(Target { host, port })
}

fn make_response(key: &[u8; 16], iv: &[u8; 16], auth: u8) -> io::Result<[u8; 38]> {
    let key = crypto::derive_response(key);
    let iv = crypto::derive_response(iv);
    let mut output = [0; 38];
    let nonce: [u8; 12] = crypto::kdf(&iv, &[b"AEAD Resp Header Len IV"])[..12]
        .try_into()
        .expect("固定长度");
    let cipher = crypto::Cipher::new(3, &crypto::kdf16(&key, &[b"AEAD Resp Header Len Key"]))?;
    output[..18].copy_from_slice(&cipher.seal(&nonce, &[], &[0, 4])?);
    let nonce: [u8; 12] = crypto::kdf(&iv, &[b"AEAD Resp Header IV"])[..12]
        .try_into()
        .expect("固定长度");
    let cipher = crypto::Cipher::new(3, &crypto::kdf16(&key, &[b"AEAD Resp Header Key"]))?;
    output[18..].copy_from_slice(&cipher.seal(&nonce, &[], &[auth, 0, 0, 0])?);
    Ok(output)
}

impl Accepted {
    /// 目标/模式准入后调用。游标保留短写和取消进度，完成后调用不会重复输出。
    pub(crate) async fn reply<S: AsyncWrite + Unpin>(&mut self, io: &mut S) -> io::Result<()> {
        if self.reply_failed {
            return Err(invalid("VMess 响应已失败"));
        }
        if self.replied {
            return Ok(());
        }
        while self.response_offset < self.response.len() {
            match io.write(&self.response[self.response_offset..]).await {
                Ok(0) => {
                    self.reply_failed = true;
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "VMess 响应写入失败",
                    ));
                }
                Ok(count) => self.response_offset += count,
                Err(error) => {
                    self.reply_failed = true;
                    return Err(error);
                }
            }
        }
        match io.flush().await {
            Ok(()) => {
                self.replied = true;
                Ok(())
            }
            Err(error) => {
                self.reply_failed = true;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests;
