//! TUIC v5 出站 UDP（QUIC 单向流）会话层。
//!
//! 与 [`tuic_udp`](crate::transport::tuic_udp) 的数据报承载并列，本模块实现
//! `udp_relay_mode: "quic"`：客户端为每条 UDP 消息打开一条单向流，写入完整的
//! `版本(5) + Packet(2) + session u16 + packet u16 + fragment_total u8 +
//!  fragment_id u8 + data_len u16 + 地址 + 数据`，随后 `finish()`；服务端以
//! 另一条单向流回包，接收端在 [`StreamReceiver::recv`] 中解析。
//!
//! 单向流承载不存在分片：每条消息固定写作 `fragment_total = 1`、
//! `fragment_id = 0`。发送端维护递增的 packet ID；两端共享同一个随机非零
//! session ID，接收端据此过滤混入的其它会话消息。
//!
//! 资源策略：每条回包流都有读取超时与最大字节上限，且接收循环一次只持有一条
//! 流；版本、命令、长度、地址或分片字段非法的消息全部丢弃后继续，不信任对端
//! 输入。连接关闭时统一返回 [`io::ErrorKind::UnexpectedEof`]。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use quinn::{Connection, VarInt};
use tokio::time::timeout;

use crate::session::{Host, Target};

use super::tuic::wire::{self, WireAddress};

/// 单条回包流的读取超时，避免半开流长期占用接收循环。
const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// 单条发送流的打开/写入超时，避免被 QUIC 流控永久阻塞。
const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// 单条回包流允许的最大字节数：命令头 + 固定头 + 最长地址 + 最大载荷。
const MAX_FRAME_LEN: usize = 2 + wire::UDP_FIXED_LEN + wire::MAX_ADDRESS_LEN + wire::MAX_UDP_DATA;

/// TUIC UDP 单向流发送端。
///
/// 持有一条已认证的 QUIC 连接与一个随机的非零 session ID；每次
/// [`send`](Self::send) 打开一条新的客户端单向流，写入一条完整的 Packet
/// 消息后结束流。载荷上限与地址校验复用 [`wire`] 的常量与编码函数。
pub(crate) struct StreamSender {
    connection: Connection,
    session_id: u16,
    packet_id: u16,
}

impl StreamSender {
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
    /// 每条消息占用一条新的客户端单向流；`fragment_total`/`fragment_id`
    /// 固定为 1/0，因为单向流承载不做分片。无论发送是否成功，packet ID
    /// 都会前进，避免重试时与服务端尚未处理完的旧消息混淆。
    pub(crate) async fn send(&mut self, target: &Target, payload: &[u8]) -> io::Result<()> {
        let destination = wire_address(target)?;
        if payload.len() > wire::MAX_UDP_DATA {
            return Err(invalid("TUIC UDP 载荷超限"));
        }

        let packet_id = self.packet_id;
        self.packet_id = self.packet_id.wrapping_add(1);

        let body = wire::encode_udp_body(self.session_id, packet_id, 1, 0, &destination, payload)
            .map_err(wire_error)?;
        let mut frame = Vec::with_capacity(2 + body.len());
        frame.push(wire::VERSION);
        frame.push(wire::COMMAND_PACKET);
        frame.extend_from_slice(&body);

        let mut stream = timeout(STREAM_WRITE_TIMEOUT, self.connection.open_uni())
            .await
            .map_err(|_| timed_out())?
            .map_err(|error| io::Error::other(format!("TUIC UDP 单向流打开失败: {error}")))?;
        timeout(STREAM_WRITE_TIMEOUT, stream.write_all(&frame))
            .await
            .map_err(|_| timed_out())?
            .map_err(|error| io::Error::other(format!("TUIC UDP 单向流写入失败: {error}")))?;
        stream
            .finish()
            .map_err(|error| io::Error::other(format!("TUIC UDP 单向流结束失败: {error}")))?;
        Ok(())
    }
}

/// TUIC UDP 单向流接收端。
///
/// 循环接受服务端打开的单向流，只接受与构造时 session ID 相同、版本/命令/
/// 长度/地址均合法的未分片 Packet 消息。连接关闭时返回
/// [`io::ErrorKind::UnexpectedEof`]；单条流超时、被重置、超限或格式非法时
/// 只丢弃该流并继续等待。
pub(crate) struct StreamReceiver {
    connection: Connection,
    session_id: u16,
}

impl StreamReceiver {
    /// 基于一条已认证的 QUIC 连接与发送端共享的 session ID 创建接收端。
    pub(crate) fn new(connection: Connection, session_id: u16) -> Self {
        Self {
            connection,
            session_id,
        }
    }

    /// 读取下一条完整的 UDP 消息。
    ///
    /// 每次只接受并处理一条回包流，读取受 `STREAM_READ_TIMEOUT` 与
    /// `MAX_FRAME_LEN` 约束；不合法的流会被停止并丢弃。只有连接关闭才
    /// 返回错误，以区分单个流的异常与整个会话的结束。
    pub(crate) async fn recv(&mut self) -> io::Result<(Target, Vec<u8>)> {
        loop {
            // `accept_uni` 在空闲时应当挂起等待（由连接空闲超时兜底），
            // 因此这里不额外加超时；返回错误即表示整条连接已不可用。
            let mut stream = self.connection.accept_uni().await.map_err(|_| closed())?;

            let reading = timeout(STREAM_READ_TIMEOUT, stream.read_to_end(MAX_FRAME_LEN));
            let frame = match reading.await {
                Ok(Ok(frame)) => frame,
                Ok(Err(_)) => {
                    // 连接已关闭时统一上报 EOF；否则只是单条流异常
                    // （被重置或超过字节上限），停止该流后继续等待。
                    if self.connection.close_reason().is_some() {
                        return Err(closed());
                    }
                    let _ = stream.stop(VarInt::from_u32(0));
                    continue;
                }
                Err(_) => {
                    // 超时的半开流主动停止，避免继续占用接收窗口。
                    let _ = stream.stop(VarInt::from_u32(0));
                    continue;
                }
            };

            let message = match parse_frame(&frame, self.session_id) {
                Some((destination, payload)) => match target_from_wire(&destination) {
                    Ok(target) => (target, payload),
                    Err(_) => continue,
                },
                None => continue,
            };
            return Ok(message);
        }
    }
}

/// 解析一条回包流并做 session ID 过滤；任何不合法输入都返回 `None`。
///
/// 校验顺序与数据报接收端一致：命令头（含版本）、固定头与分片字段、地址、
/// 数据长度。单向流承载不做分片，因此这里额外要求 `total = 1, id = 0`。
fn parse_frame(frame: &[u8], session_id: u16) -> Option<(WireAddress, Vec<u8>)> {
    if wire::decode_command_header(frame).ok()? != wire::Command::Packet {
        return None;
    }
    let body = wire::decode_udp_body(&frame[2..]).ok()?;
    if body.session_id != session_id {
        return None;
    }
    if body.fragment_total != 1 || body.fragment_id != 0 {
        return None;
    }
    Some((body.destination, body.payload.to_vec()))
}

/// 为一条 QUIC 连接创建配套的 UDP 流发送端与接收端。
///
/// 两端共享同一个随机非零 session ID；QUIC 连接本身可廉价克隆，调用方
/// 不需要拆分连接所有权。
pub(crate) fn split(connection: Connection) -> io::Result<(StreamSender, StreamReceiver)> {
    let sender = StreamSender::new(connection.clone())?;
    let receiver = StreamReceiver::new(connection, sender.session_id());
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

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn wire_error(error: wire::WireError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "TUIC UDP 流连接已关闭")
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "TUIC UDP 单向流操作超时")
}
