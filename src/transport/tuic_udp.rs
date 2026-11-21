//! TUIC v5 出站 UDP（QUIC DATAGRAM）会话层。
//!
//! 本模块只负责 UDP 关联在数据报上的消息编解码与分片重组，复用
//! [`wire`](crate::transport::tuic::wire) 的 TUIC 私有线格式：
//! `版本(5) + Packet(2) + session u16 + packet u16 + fragment_total u8 +
//!  fragment_id u8 + data_len u16 + 地址 + 数据`。
//! 地址只出现在 `fragment_id == 0` 的分片里，其余分片使用 `Empty` 地址。
//!
//! 使用方式：一条 QUIC 连接上为每个本地 UDP 关联调用一次 [`split`]，
//! 得到发送端和接收端；发送端维护递增的 packet ID，接收端只接受同
//! session ID 的分片并在内部完成重组。两端可各自放进独立任务，互不阻塞。
//!
//! 资源策略与仓库内服务端实现保持一致：重组组数、总字节数、分片数全部有界，
//! 任何版本/命令/地址/长度/分片错误都直接丢弃该数据报，不信任对端输入。

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::Connection;
use tokio::time::timeout;

use crate::session::{Host, Target};

use super::tuic::wire::{self, WireAddress};

/// 单次数据报发送的超时，避免被 QUIC 流控永久阻塞。
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// 同一会话同时保留的分片重组组数。
const MAX_REASSEMBLY_GROUPS: usize = 16;
/// 同一会话分片重组占用的总字节上限。
const MAX_REASSEMBLY_BYTES: usize = 128 * 1024;
/// 未完成的重组组在该时间后被丢弃，防止半包长期占用内存。
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

/// TUIC UDP 发送端。
///
/// 持有一条 QUIC 连接与一个随机的非零 session ID；每次 [`send`](Self::send)
/// 使用一个新的 packet ID，并在超过路径 MTU 时自动分片。
pub(crate) struct UdpSessionSender {
    connection: Connection,
    session_id: u16,
    packet_id: u16,
}

impl UdpSessionSender {
    /// 基于一条已认证的 QUIC 连接创建发送端，同时生成随机非零 session ID。
    pub(crate) fn new(connection: Connection) -> io::Result<Self> {
        Ok(Self {
            connection,
            session_id: random_session_id()?,
            packet_id: 0,
        })
    }

    /// 当前会话的 session ID，接收端必须使用同一个值过滤。
    pub(crate) fn session_id(&self) -> u16 {
        self.session_id
    }

    /// 发送一条 UDP 消息。
    ///
    /// `target` 是这条消息的目的地址，`payload` 是完整的 UDP 载荷；载荷超过
    /// 单个数据报容量时按 `fragment_total`/`fragment_id` 分片发送。空载荷
    /// 也会发送一个合法的零长度分片。
    pub(crate) async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        let destination = wire_address(target)?;
        if payload.len() > wire::MAX_UDP_DATA {
            return Err(invalid("TUIC UDP 载荷超限"));
        }
        let maximum = self
            .connection
            .max_datagram_size()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "TUIC 对端未协商数据报"))?;
        // 每个数据报都要携带版本/命令、固定头与地址；首分片地址最长，
        // 后续分片虽然更短，仍按首分片的容量切分以保持实现简单。
        let header = 2 + wire::UDP_FIXED_LEN + wire::address_len(&destination);
        if maximum <= header {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUIC 数据报容量不足",
            ));
        }
        let chunk = maximum - header;
        let total = if payload.is_empty() {
            1
        } else {
            payload.len().div_ceil(chunk)
        };
        if total > usize::from(wire::MAX_FRAGMENTS) {
            return Err(invalid("TUIC UDP 分片过多"));
        }

        // 同一消息的所有分片共用一个 packet ID；无论发送是否成功都前进，
        // 避免重试时与仍在重组中的旧分片混淆。
        let packet_id = self.packet_id;
        self.packet_id = self.packet_id.wrapping_add(1);

        if total == 1 {
            return self
                .send_fragment(packet_id, 1, 0, &destination, payload)
                .await;
        }
        for (index, part) in payload.chunks(chunk).enumerate() {
            let fragment = if index == 0 {
                destination.clone()
            } else {
                WireAddress::Empty
            };
            self.send_fragment(packet_id, total as u8, index as u8, &fragment, part)
                .await?;
        }
        Ok(())
    }

    /// 编码并发送一个分片；数据报模式不重传，失败直接返回调用方。
    async fn send_fragment(
        &self,
        packet_id: u16,
        fragment_total: u8,
        fragment_id: u8,
        destination: &WireAddress,
        payload: &[u8],
    ) -> io::Result<()> {
        let body = wire::encode_udp_body(
            self.session_id,
            packet_id,
            fragment_total,
            fragment_id,
            destination,
            payload,
        )
        .map_err(wire_error)?;
        let mut frame = Vec::with_capacity(2 + body.len());
        frame.push(wire::VERSION);
        frame.push(wire::COMMAND_PACKET);
        frame.extend_from_slice(&body);
        timeout(
            SEND_TIMEOUT,
            self.connection.send_datagram_wait(Bytes::from(frame)),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TUIC UDP 发送超时"))?
        .map_err(|error| io::Error::other(format!("TUIC UDP 发送失败: {error}")))
    }
}

/// TUIC UDP 接收端。
///
/// 只接受与构造时 session ID 相同的 `Packet` 数据报；按 packet ID 与
/// fragment ID 重组后返回目标地址和完整载荷。连接关闭时返回
/// [`io::ErrorKind::UnexpectedEof`]。
pub(crate) struct UdpSessionReceiver {
    connection: Connection,
    session_id: u16,
    reassembly: Reassembly,
}

impl UdpSessionReceiver {
    /// 基于一条已认证的 QUIC 连接与发送端共享的 session ID 创建接收端。
    pub(crate) fn new(connection: Connection, session_id: u16) -> Self {
        Self {
            connection,
            session_id,
            reassembly: Reassembly::new(),
        }
    }

    /// 读取并重组下一条完整 UDP 消息。
    ///
    /// 版本不符、命令不是 `Packet`、session ID 不匹配、分片字段非法或超过
    /// 重组上限的数据报都会被丢弃，然后继续等待；只有连接关闭才返回错误。
    pub(crate) async fn recv(&mut self) -> io::Result<(Target, Vec<u8>)> {
        loop {
            let datagram = self
                .connection
                .read_datagram()
                .await
                .map_err(|_| closed())?;
            // 每次收到数据报顺手清理过期半包；开销与组数成正比且有上界。
            self.reassembly.expire();

            let command = match wire::decode_command_header(&datagram) {
                Ok(command) => command,
                Err(_) => continue,
            };
            if command != wire::Command::Packet {
                // 心跳等其它命令与本会话无关，直接忽略。
                continue;
            }
            let body = match wire::decode_udp_body(&datagram[2..]) {
                Ok(body) => body,
                Err(_) => continue,
            };
            if body.session_id != self.session_id {
                continue;
            }
            // 分片字段已由 `decode_udp_body` 校验；这里再按本模块的重组
            // 内存上限做约束。
            let Some((destination, payload)) = self.reassembly.feed(
                body.packet_id,
                body.fragment_total,
                body.fragment_id,
                body.destination,
                body.payload,
            ) else {
                continue;
            };
            let target = match target_from_wire(&destination) {
                Ok(target) => target,
                Err(_) => continue,
            };
            return Ok((target, payload));
        }
    }
}

/// 为一条 QUIC 连接创建配套的 UDP 会话发送端与接收端。
///
/// 两端共享同一个随机非零 session ID；QUIC 连接本身可廉价克隆，调用方
/// 不需要拆分连接所有权。
pub(crate) fn split(connection: Connection) -> io::Result<(UdpSessionSender, UdpSessionReceiver)> {
    let sender = UdpSessionSender::new(connection.clone())?;
    let receiver = UdpSessionReceiver::new(connection, sender.session_id());
    Ok((sender, receiver))
}

/// 生成随机的非零 session ID；零值保留给上游的 Empty/未指定语义。
fn random_session_id() -> io::Result<u16> {
    let mut bytes = [0u8; 2];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| io::Error::other("TUIC UDP 会话 ID 生成失败"))?;
    let id = u16::from_be_bytes(bytes);
    Ok(if id == 0 { 1 } else { id })
}

/// 把本地目标转换为 TUIC 线格式地址。
fn wire_address(target: &Target) -> io::Result<WireAddress> {
    if target.port == 0 {
        return Err(invalid("TUIC UDP 目标端口为 0"));
    }
    Ok(match &target.host {
        Host::Ip(IpAddr::V4(ip)) => WireAddress::Ipv4 {
            octets: ip.octets(),
            port: target.port,
        },
        Host::Ip(IpAddr::V6(ip)) => WireAddress::Ipv6 {
            octets: ip.octets(),
            port: target.port,
        },
        Host::Domain(domain) => WireAddress::Domain {
            name: domain.clone(),
            port: target.port,
        },
    })
}

/// 把线格式地址转换为 [`Target`]；域名同样走 [`Host::parse`] 的严格校验。
fn target_from_wire(address: &WireAddress) -> io::Result<Target> {
    match address {
        WireAddress::Empty => Err(invalid("TUIC UDP 目标地址为空")),
        WireAddress::Ipv4 { octets, port } => {
            target_from_parts(Host::Ip(IpAddr::V4(Ipv4Addr::from(*octets))), *port)
        }
        WireAddress::Ipv6 { octets, port } => {
            target_from_parts(Host::Ip(IpAddr::V6(Ipv6Addr::from(*octets))), *port)
        }
        WireAddress::Domain { name, port } => {
            let host = Host::parse(name).ok_or_else(|| invalid("TUIC UDP 目标域名无效"))?;
            target_from_parts(host, *port)
        }
    }
}

fn target_from_parts(host: Host, port: u16) -> io::Result<Target> {
    if port == 0 {
        return Err(invalid("TUIC UDP 目标端口为 0"));
    }
    Ok(Target { host, port })
}

/// 单个 packet ID 的重组状态。
struct Group {
    total: u8,
    parts: Vec<Option<Vec<u8>>>,
    received: u8,
    bytes: usize,
    /// 只有首分片携带目的地址；后续分片是 `Empty`。
    destination: Option<WireAddress>,
    updated: Instant,
}

impl Group {
    fn new(total: u8) -> Self {
        Self {
            total,
            parts: (0..total).map(|_| None).collect(),
            received: 0,
            bytes: 0,
            destination: None,
            updated: Instant::now(),
        }
    }
}

/// 分片重组表；组数、总字节和单组载荷都有严格上限。
struct Reassembly {
    groups: HashMap<u16, Group>,
    bytes: usize,
}

impl Reassembly {
    fn new() -> Self {
        Self {
            groups: HashMap::new(),
            bytes: 0,
        }
    }

    /// 输入一个已通过线格式校验的分片，返回完成后的完整消息。
    ///
    /// 未完成、重复、超限或非法的分片返回 `None`，由调用方静默丢弃。
    fn feed(
        &mut self,
        packet_id: u16,
        fragment_total: u8,
        fragment_id: u8,
        destination: WireAddress,
        payload: &[u8],
    ) -> Option<(WireAddress, Vec<u8>)> {
        // 首分片必须带地址；其余分片允许携带 Empty，携带其它地址也不会
        // 覆盖首分片记录的地址。
        if fragment_id == 0 && matches!(destination, WireAddress::Empty) {
            return None;
        }

        if fragment_total <= 1 {
            // 未分片消息在线上必须写作 total=1、id=0；其它编号一律丢弃。
            if fragment_id != 0
                || matches!(destination, WireAddress::Empty)
                || payload.len() > wire::MAX_UDP_DATA
            {
                return None;
            }
            return Some((destination, payload.to_vec()));
        }

        // 同一 packet ID 出现不同的总片数时，以最新声明为准重新开始，
        // 与服务端行为一致；旧的半包立即释放。
        let mismatched = self
            .groups
            .get(&packet_id)
            .is_some_and(|group| group.total != fragment_total);
        if mismatched && let Some(group) = self.groups.remove(&packet_id) {
            self.bytes = self.bytes.saturating_sub(group.bytes);
        }
        if !self.groups.contains_key(&packet_id) {
            // 组数已满时淘汰最久未更新的组，保证攻击者无法无限占用内存。
            if self.groups.len() >= MAX_REASSEMBLY_GROUPS {
                self.evict_oldest();
            }
            self.groups.insert(packet_id, Group::new(fragment_total));
        }

        let mut added = 0usize;
        let mut overflow = false;
        {
            let group = self.groups.get_mut(&packet_id)?;
            let index = usize::from(fragment_id);
            if index >= group.parts.len() || group.parts[index].is_some() {
                // 重复分片或编号越界：只丢弃当前分片，不破坏已有进度。
                return None;
            }
            let length = payload.len();
            if group.bytes.saturating_add(length) > wire::MAX_UDP_DATA
                || self.bytes.saturating_add(length) > MAX_REASSEMBLY_BYTES
            {
                overflow = true;
            } else {
                group.bytes += length;
                group.received += 1;
                group.updated = Instant::now();
                if fragment_id == 0 {
                    group.destination = Some(destination);
                }
                group.parts[index] = Some(payload.to_vec());
                added = length;
            }
        }
        if overflow {
            // 超过单组或全局上限时整组丢弃，避免半包继续占用预算。
            if let Some(group) = self.groups.remove(&packet_id) {
                self.bytes = self.bytes.saturating_sub(group.bytes);
            }
            return None;
        }
        self.bytes = self.bytes.saturating_add(added);

        let complete = self
            .groups
            .get(&packet_id)
            .is_some_and(|group| group.received == group.total);
        if !complete {
            return None;
        }
        let group = self.groups.remove(&packet_id)?;
        self.bytes = self.bytes.saturating_sub(group.bytes);
        let destination = group.destination?;
        let mut payload = Vec::with_capacity(group.bytes);
        for part in group.parts {
            payload.extend_from_slice(&part?);
        }
        if payload.len() > wire::MAX_UDP_DATA {
            return None;
        }
        Some((destination, payload))
    }

    /// 丢弃最久未更新的组；仅在组数达到上限时调用。
    fn evict_oldest(&mut self) {
        let oldest = self
            .groups
            .iter()
            .min_by_key(|(_, group)| group.updated)
            .map(|(packet_id, _)| *packet_id);
        if let Some(packet_id) = oldest
            && let Some(group) = self.groups.remove(&packet_id)
        {
            self.bytes = self.bytes.saturating_sub(group.bytes);
        }
    }

    /// 清理超时半包并重新累计字节数。
    fn expire(&mut self) {
        let now = Instant::now();
        let mut bytes = 0usize;
        self.groups.retain(|_, group| {
            if now.duration_since(group.updated) < REASSEMBLY_TIMEOUT {
                bytes = bytes.saturating_add(group.bytes);
                true
            } else {
                false
            }
        });
        self.bytes = bytes;
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn wire_error(error: wire::WireError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "TUIC UDP 连接已关闭")
}
