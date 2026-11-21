//! Hysteria2 出站 UDP 会话层（UDP over QUIC DATAGRAM）。
//!
//! 复用 `wire` 模块定义的线格式：
//!
//! ```text
//! sessionID(4, 大端) | packetID(2, 大端) | fragmentID(1) |
//! fragmentTotal(1) | 目标长度(varint) | 目标字符串 | 载荷...
//! ```
//!
//! 一个 `UdpSession` 对应一个随机生成的会话 ID。发送端按 `wire::UDP_MTU`
//! 自动把一条 UDP 载荷切分为多个 DATAGRAM；接收端只处理本会话 ID 的报文，
//! 并按 `(packetID, fragmentID)` 重组。任何解码失败、目标非法、分片不一致
//! 的报文都会被静默丢弃，接收循环不会 panic。
//!
//! 本模块不实现 Brutal/BBR 与 0-RTT，只负责在已认证的 QUIC 连接上收发
//! DATAGRAM；拥塞控制沿用 quinn 的默认实现。

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use quinn::Connection;

use crate::session::{Host, Target};

use super::wire;

/// 并发重组条目上限；每项载荷最多 `MAX_UDP_PAYLOAD`，因此载荷内存
/// 上界与 `MAX_REASSEMBLY_BYTES` 一致。
const MAX_REASSEMBLY_ENTRIES: usize = 64;
/// 全部重组条目允许占用的载荷字节数上限（按载荷统计，不含少量元数据）。
const MAX_REASSEMBLY_BYTES: usize = 256 * 1024;
/// 半成品重组条目的存活时间；超时后丢弃，避免对端只发一半分片占住内存。
const REASSEMBLY_TTL: Duration = Duration::from_secs(8);

/// 使用现有密码学后端的随机源，不另行设计会话 ID 随机生成器。
fn random_session_id() -> io::Result<u32> {
    loop {
        let mut bytes = [0; 4];
        aws_lc_rs::rand::fill(&mut bytes)
            .map_err(|_| io::Error::other("Hysteria2 无法生成 UDP 会话 ID"))?;
        let id = u32::from_be_bytes(bytes);
        if id != 0 {
            return Ok(id);
        }
    }
}

fn validate_session_id(session_id: u32) -> io::Result<()> {
    if session_id == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hysteria2 UDP 会话 ID 不得为 0",
        ));
    }
    Ok(())
}

/// 把目标编码为 Hysteria2 线上的 `host:port`（IPv6 自动加方括号）。
fn destination(target: &Target) -> String {
    let host = match &target.host {
        Host::Ip(ip) => ip.to_string(),
        Host::Domain(domain) => domain.clone(),
    };
    wire::format_host_port(&host, target.port)
}

/// 把线上目标字符串还原为 `Target`；端口 0 与非法主机名一律拒绝。
fn target_from_wire(destination: &str) -> io::Result<Target> {
    let (host, port) = wire::parse_host_port(destination)?;
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria2 UDP 目标端口为 0",
        ));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Target {
            host: Host::Ip(ip),
            port,
        });
    }
    if host.is_empty() || host.len() > 255 || !host.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hysteria2 UDP 目标域名无效",
        ));
    }
    Ok(Target {
        host: Host::Domain(host.to_ascii_lowercase()),
        port,
    })
}

/// quinn 发送错误到 `io::Error` 的映射；保留可区分的错误类别。
fn send_error(error: quinn::SendDatagramError) -> io::Error {
    match error {
        quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled => {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "Hysteria2 对端不支持 QUIC DATAGRAM",
            )
        }
        quinn::SendDatagramError::TooLarge => io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hysteria2 UDP DATAGRAM 超出路径上限",
        ),
        quinn::SendDatagramError::ConnectionLost(_) => {
            io::Error::new(io::ErrorKind::BrokenPipe, "Hysteria2 QUIC 连接已关闭")
        }
    }
}

/// 一个 UDP 会话的发送端。
///
/// 每次 `send` 编码一条完整的 UDP 消息；超过 `wire::UDP_MTU` 时自动分片，
/// 同一消息的所有分片共享同一个 `packetID`，`fragmentID` 从 0 开始。
pub(crate) struct UdpSessionSender {
    connection: Connection,
    session_id: u32,
    packet_id: u16,
}

impl UdpSessionSender {
    /// 使用显式会话 ID 创建发送端；ID 必须非 0。
    pub(crate) fn with_session_id(connection: Connection, session_id: u32) -> io::Result<Self> {
        validate_session_id(session_id)?;
        Ok(Self {
            connection,
            session_id,
            packet_id: 0,
        })
    }

    /// 发送一条 UDP 载荷。
    ///
    /// `packetID` 在编码前先递增，保证即使发送中途失败，下一条消息也不会
    /// 与残留分片共用 ID。空载荷也会编码成一条合法的单分片消息。
    pub(crate) async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        if target.port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Hysteria2 UDP 目标端口为 0",
            ));
        }
        let endpoint = destination(target);
        // 先占用并推进 packetID，避免失败后复用 ID。
        let packet_id = self.packet_id;
        self.packet_id = self.packet_id.wrapping_add(1);
        let fragments = wire::fragment_udp_message(
            self.session_id,
            packet_id,
            &endpoint,
            payload,
            wire::UDP_MTU,
        )?;
        for fragment in fragments {
            self.connection
                .send_datagram_wait(fragment.into())
                .await
                .map_err(send_error)?;
        }
        Ok(())
    }
}

/// 一个 UDP 会话的接收端。
///
/// `recv` 只返回本会话 ID 的完整消息；其余会话、非法报文和不完整分片都会
/// 被丢弃。连接关闭（包括本地 close、对端关闭、空闲超时）时返回
/// `ErrorKind::UnexpectedEof`，调用方可据此结束读取。
pub(crate) struct UdpSessionReceiver {
    connection: Connection,
    session_id: u32,
    reassembler: Reassembler,
}

impl UdpSessionReceiver {
    /// 使用显式会话 ID 创建接收端；ID 必须非 0。
    pub(crate) fn with_session_id(connection: Connection, session_id: u32) -> io::Result<Self> {
        validate_session_id(session_id)?;
        Ok(Self {
            connection,
            session_id,
            reassembler: Reassembler::default(),
        })
    }

    /// 等待下一条完整的 UDP 消息。
    ///
    /// 该 future 只在 `read_datagram` 上等待，可安全放入 `tokio::select!`；
    /// 取消（丢弃 future）不会破坏重组状态。连接关闭时返回
    /// `ErrorKind::UnexpectedEof`。
    pub(crate) async fn recv(&mut self) -> io::Result<(Target, Vec<u8>)> {
        loop {
            let datagram = self.connection.read_datagram().await.map_err(|_| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "Hysteria2 UDP 连接已关闭")
            })?;
            let message = match wire::decode_udp_message(&datagram) {
                Ok(message) => message,
                // 非法报文直接丢弃，不中断会话。
                Err(_) => continue,
            };
            if message.session_id != self.session_id {
                continue;
            }
            let target = match target_from_wire(message.destination) {
                Ok(target) => target,
                Err(_) => continue,
            };
            if let Some(payload) = self.reassembler.feed(&message) {
                return Ok((target, payload));
            }
        }
    }
}

/// 一条 UDP 会话的收发两端。
///
/// 构造时生成共享的会话 ID；`into_split` 后发送与接收可分别放进不同任务。
pub(crate) struct UdpSession {
    sender: UdpSessionSender,
    receiver: UdpSessionReceiver,
}

impl UdpSession {
    /// 在已认证的 QUIC 连接上创建一个 UDP 会话。
    pub(crate) fn new(connection: Connection) -> io::Result<Self> {
        let session_id = random_session_id()?;
        Ok(Self {
            sender: UdpSessionSender::with_session_id(connection.clone(), session_id)?,
            receiver: UdpSessionReceiver::with_session_id(connection, session_id)?,
        })
    }

    /// 拆分为发送端与接收端。
    pub(crate) fn into_split(self) -> (UdpSessionSender, UdpSessionReceiver) {
        (self.sender, self.receiver)
    }
}

/// 在给定 QUIC 连接上创建共享同一个随机会话 ID 的收发端。
///
/// 等价于 `UdpSession::new(connection)?.into_split()`，方便只需要 split
/// 接口的调用方直接使用。
pub(crate) fn split(connection: Connection) -> io::Result<(UdpSessionSender, UdpSessionReceiver)> {
    Ok(UdpSession::new(connection)?.into_split())
}

/// UDP 分片重组器。
///
/// 只保留半成品条目；每个条目受 `MAX_FRAGMENTS`、`MAX_UDP_PAYLOAD` 约束，
/// 全局受条目数、载荷字节数和 TTL 约束，因此对端无法靠伪造分片无限占用内存。
#[derive(Default)]
struct Reassembler {
    /// 键为 packetID；调用方已按会话 ID 过滤，故无需再带 sessionID。
    entries: HashMap<u16, FragmentEntry>,
    /// 当前所有条目占用的载荷字节数。
    bytes: usize,
    last_sweep: Option<Instant>,
}

struct FragmentEntry {
    total: u8,
    received: u8,
    destination: String,
    chunks: Vec<Option<Vec<u8>>>,
    bytes: usize,
    created: Instant,
}

impl Reassembler {
    /// 喂入一条分片；仅当消息完整时返回重组后的载荷。
    fn feed(&mut self, message: &wire::UdpMessage<'_>) -> Option<Vec<u8>> {
        // decode_udp_message 已保证 fragment_total >= 1。
        if message.fragment_total <= 1 {
            return Some(message.payload.to_vec());
        }
        if message.fragment_total > wire::MAX_FRAGMENTS {
            return None;
        }
        let payload_len = message.payload.len();
        if payload_len > wire::MAX_UDP_PAYLOAD {
            return None;
        }

        let now = Instant::now();
        if self
            .last_sweep
            .is_none_or(|last| now.saturating_duration_since(last) >= REASSEMBLY_TTL / 2)
        {
            self.sweep(now);
        }

        let key = message.packet_id;
        let index = usize::from(message.fragment_id);
        if !self.entries.contains_key(&key) {
            if !self.make_room(payload_len) {
                return None;
            }
            self.entries.insert(
                key,
                FragmentEntry {
                    total: message.fragment_total,
                    received: 0,
                    destination: message.destination.to_owned(),
                    chunks: vec![None; usize::from(message.fragment_total)],
                    bytes: 0,
                    created: now,
                },
            );
        }

        let mut invalid = false;
        let mut added = false;
        let mut complete = false;
        {
            let entry = self.entries.get_mut(&key)?;
            if entry.total != message.fragment_total
                || entry.destination != message.destination
                || index >= entry.chunks.len()
            {
                // 同一 packetID 的分片元数据必须完全一致，否则整条消息作废。
                invalid = true;
            } else if entry.chunks[index].is_none() {
                if entry.bytes.saturating_add(payload_len) > wire::MAX_UDP_PAYLOAD {
                    invalid = true;
                } else {
                    entry.chunks[index] = Some(message.payload.to_vec());
                    entry.bytes = entry.bytes.saturating_add(payload_len);
                    entry.received = entry.received.saturating_add(1);
                    added = true;
                    complete = entry.received >= entry.total;
                }
            }
            // 重复分片直接忽略：槽位已占用，不重复计数也不扩大内存。
        }

        if invalid {
            if let Some(entry) = self.entries.remove(&key) {
                self.bytes = self.bytes.saturating_sub(entry.bytes);
            }
            return None;
        }
        if added {
            self.bytes = self.bytes.saturating_add(payload_len);
        }
        if !complete {
            return None;
        }

        let entry = self.entries.remove(&key)?;
        self.bytes = self.bytes.saturating_sub(entry.bytes);
        if entry.bytes > wire::MAX_UDP_PAYLOAD {
            return None;
        }
        let mut output = Vec::with_capacity(entry.bytes);
        for chunk in entry.chunks.into_iter().flatten() {
            output.extend_from_slice(&chunk);
        }
        if output.len() != entry.bytes || output.len() > wire::MAX_UDP_PAYLOAD {
            return None;
        }
        Some(output)
    }

    /// 为新条目腾出条目数与载荷字节额度；腾不出则拒绝。
    fn make_room(&mut self, additional: usize) -> bool {
        if additional > MAX_REASSEMBLY_BYTES {
            return false;
        }
        while self.entries.len() >= MAX_REASSEMBLY_ENTRIES
            || self.bytes.saturating_add(additional) > MAX_REASSEMBLY_BYTES
        {
            if !self.evict_oldest() {
                return false;
            }
        }
        true
    }

    /// 清理超过 TTL 的条目，并同步扣减字节计数。
    fn sweep(&mut self, now: Instant) {
        let mut removed = 0usize;
        self.entries.retain(|_, entry| {
            let keep = now.saturating_duration_since(entry.created) < REASSEMBLY_TTL;
            if !keep {
                removed = removed.saturating_add(entry.bytes);
            }
            keep
        });
        self.bytes = self.bytes.saturating_sub(removed);
        self.last_sweep = Some(now);
    }

    /// 淘汰创建时间最早的条目；空表时返回 false。
    fn evict_oldest(&mut self) -> bool {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.created)
            .map(|(key, _)| *key);
        match oldest {
            Some(key) => {
                if let Some(entry) = self.entries.remove(&key) {
                    self.bytes = self.bytes.saturating_sub(entry.bytes);
                }
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message<'a>(
        session_id: u32,
        packet_id: u16,
        fragment_id: u8,
        fragment_total: u8,
        destination: &'a str,
        payload: &'a [u8],
    ) -> wire::UdpMessage<'a> {
        wire::UdpMessage {
            session_id,
            packet_id,
            fragment_id,
            fragment_total,
            destination,
            payload,
        }
    }

    #[test]
    fn single_fragment_returns_payload() {
        let mut reassembler = Reassembler::default();
        let payload = b"hello";
        let message = message(1, 7, 0, 1, "example.com:53", payload);
        assert_eq!(reassembler.feed(&message), Some(payload.to_vec()));
    }

    #[test]
    fn out_of_order_fragments_reassemble() {
        let mut reassembler = Reassembler::default();
        let first = message(1, 8, 0, 2, "example.com:53", b"abc");
        let second = message(1, 8, 1, 2, "example.com:53", b"def");
        assert!(reassembler.feed(&second).is_none());
        assert_eq!(reassembler.feed(&first), Some(b"abcdef".to_vec()));
        assert!(reassembler.entries.is_empty());
        assert_eq!(reassembler.bytes, 0);
    }

    #[test]
    fn mismatched_destination_drops_message() {
        let mut reassembler = Reassembler::default();
        let first = message(1, 9, 0, 2, "example.com:53", b"abc");
        let second = message(1, 9, 1, 2, "other.com:53", b"def");
        assert!(reassembler.feed(&first).is_none());
        assert!(reassembler.feed(&second).is_none());
        assert!(reassembler.entries.is_empty());
        assert_eq!(reassembler.bytes, 0);
    }

    #[test]
    fn session_id_is_nonzero() {
        for _ in 0..16 {
            assert_ne!(random_session_id().unwrap(), 0);
        }
    }

    #[test]
    fn target_round_trip() {
        let target = Target {
            host: Host::Domain("example.com".to_owned()),
            port: 53,
        };
        assert_eq!(destination(&target), "example.com:53");
        assert_eq!(target_from_wire("example.com:53").unwrap(), target);

        let ipv6 = Target {
            host: Host::Ip("2001:db8::1".parse().unwrap()),
            port: 443,
        };
        assert_eq!(destination(&ipv6), "[2001:db8::1]:443");
        assert_eq!(target_from_wire("[2001:db8::1]:443").unwrap(), ipv6);
    }
}
