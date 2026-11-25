//! 交给 quinn 的 UDP 套接字适配层。
//!
//! quinn 只接受 `std::net::UdpSocket` 或实现 `AsyncUdpSocket` 的抽象套接字。
//! 为了在 QUIC 之下应用 salamander obfs，本模块包装 `tokio::net::UdpSocket`：
//! - 接收：先从内核读出一个线上报文，解密后写入 quinn 提供的缓冲区；
//! - 发送：对每个 QUIC 报文单独生成 salt 与密钥后加密。
//!
//! 这里刻意关闭 GRO/GSO（每次只处理一个报文），保证每个 datagram 都有独立的
//! 随机 salt，且内存边界清晰。回调路径不执行阻塞操作。

use std::{
    fmt, io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll, ready},
    time::Instant,
};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::net::UdpSocket;

use super::{gecko, obfs};

/// 单个报文的最大线上长度；quinn 的正常 MTU 远小于此值。
const SCRATCH_LEN: usize = obfs::MAX_WIRE_PACKET + obfs::SALT_LEN;

/// 服务端启用的 obfs 层；salamander 与 gecko 互斥。
#[derive(Clone)]
pub(crate) enum ObfsMode {
    Salamander(Vec<u8>),
    Gecko {
        password: Vec<u8>,
        min_packet_size: usize,
        max_packet_size: usize,
    },
}

impl ObfsMode {
    pub(crate) fn password(&self) -> &[u8] {
        match self {
            Self::Salamander(password) | Self::Gecko { password, .. } => password,
        }
    }
}

pub(super) struct ObfsUdpSocket {
    io: Arc<UdpSocket>,
    mode: Option<ObfsMode>,
    /// 接收暂存区。quinn 的接收驱动是单任务的，用普通互斥锁即可；
    /// 即使锁中毒也恢复内部数据，不在回调路径 panic。
    scratch: Mutex<Vec<u8>>,
    /// gecko 解密后的暂存区。
    plain: Mutex<Vec<u8>>,
    reassembler: Mutex<gecko::Reassembler>,
    fragment_id: AtomicU8,
}

impl ObfsUdpSocket {
    pub(super) fn new(socket: UdpSocket, mode: Option<ObfsMode>) -> io::Result<Arc<Self>> {
        if mode.as_ref().is_some_and(|mode| mode.password().is_empty()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "obfs 密码不得为空",
            ));
        }
        Ok(Arc::new(Self {
            io: Arc::new(socket),
            mode,
            scratch: Mutex::new(vec![0u8; SCRATCH_LEN]),
            plain: Mutex::new(vec![0u8; SCRATCH_LEN]),
            reassembler: Mutex::new(gecko::Reassembler::new()),
            fragment_id: AtomicU8::new(0),
        }))
    }

    /// 无混淆时不要套这层：Linux 上标准 quinn 实现走 `sendmsg + UDP_SEGMENT`
    /// （GSO）一次发多段，本层每次只发一个报文。
    pub(super) fn endpoint(
        socket: UdpSocket,
        mode: Option<ObfsMode>,
        server: Option<quinn::ServerConfig>,
    ) -> io::Result<quinn::Endpoint> {
        let Some(mode) = mode else {
            return quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                server,
                socket.into_std()?,
                Arc::new(quinn::TokioRuntime),
            );
        };
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            server,
            Self::new(socket, Some(mode))?,
            Arc::new(quinn::TokioRuntime),
        )
    }

    fn send_wire(&self, wire: &[u8], destination: std::net::SocketAddr) -> io::Result<()> {
        match self.io.try_send_to(wire, destination) {
            Ok(written) if written == wire.len() => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "UDP 报文未完整发送",
            )),
            Err(error) => Err(error),
        }
    }
}

// 关于「无混淆也走这里」的已核实结论（2026-11，勿重复调查）：
//
// - 没有协议理由。`mode == None` 时发送原样写出、接收直接写进 Quinn 给的
//   缓冲，既不加盐也不填充，仍固定分配两块暂存区只是因为复用同一实现。
// - **macOS 上换标准 socket 不恢复批量能力。** 本仓库没有启用 `quinn-udp`
//   的 `fast-apple-datapath`（`cargo tree -e features -i quinn-udp` 只有
//   `log`/`tracing`），`BATCH_SIZE = 1`，标准实现同样一次收 1 槽、发 1 段。
// - Linux 上是真实能力恢复，且**收益几乎全来自发送端 GSO**。
//
// Linux ARM64 回环实测（`dubhe 0.1.0`，HY2 无混淆，同时改两端时的四组合
// 交替对照，4 秒窗口、同轮配对）：
//
// | 组合 | 下载 | 上传 |
// |---|---:|---:|
// | base + base | 3.30 | 3.33 |
// | **new 服务端** + base 客户端 | 3.28 | **3.93** |
// | base 服务端 + **new 客户端** | **3.85** | 3.33 |
// | new + new | 4.93 | 4.88 |
//
// 结论：**谁发送谁受益**。只换接收端（`recvmmsg`）在下载方向量不出提升；
// 换成发送端后 +17%~19%，两端都换 +47%~49%。CPU 秒/GiB 反而略降。
//
// 客户端改动已撤回（`open_udp` 每条 UDP 关联新建 endpoint，接收区会按关联
// 线性放大，需单独作容量决策），所以当前只有服务端入站走标准实现：
// 一个监听 endpoint 服务多条连接，内存摊薄。
//
// 真实客户端对照（sing-box 1.11.15 客户端 → dubhe 服务端，4 轮中位数）：
//
// | | 下载 | 上传 |
// |---|---:|---:|
// | 改前 | 2.85 | 3.25 |
// | 改后 | 2.91 | **4.41** |
//
// 下载不变是客户端未改（发送端仍是逐段发出），不是服务端接收的问题。
//
// 与 sing-box 服务端同机对照（dubhe 客户端、不声明带宽走 auto，3 轮）：
// 上传 dubhe 4.80 / sing-box 4.11，下载 dubhe 3.40 / sing-box 3.55。上传已反超。
// 双方都声明带宽走 Brutal 时 sing-box 上传仍更高（5.0 / 3.94），差距来自
// quic-go 的 20 KiB GSO 缓冲对 Quinn `MAX_TRANSMIT_SEGMENTS = 10`：实测
// dubhe 已满 10 段（线上包长 14520 = 10 × 1452），无法靠配置再放大。
//
// 另：Linux 上中继块大小对 HY2 影响很小（8/8、16/32、32/32 均为 4.6–5.0），
// 与 VLESS 对块大小敏感不同。
impl fmt::Debug for ObfsUdpSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 不输出密码。
        formatter
            .debug_struct("ObfsUdpSocket")
            .field(
                "obfs",
                &self.mode.as_ref().map(|mode| match mode {
                    ObfsMode::Salamander(_) => "salamander",
                    ObfsMode::Gecko { .. } => "gecko",
                }),
            )
            .finish()
    }
}

fn recover<T>(value: Result<T, std::sync::PoisonError<T>>) -> T {
    value.unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// quinn 按 `stride` 切分 `len`；单个数据报的 stride 必须等于长度，
/// 0 会产生空切片并进入驱动的死循环。
fn set_meta(
    metadata: &mut RecvMeta,
    address: std::net::SocketAddr,
    length: usize,
) -> io::Result<()> {
    metadata.addr = address;
    metadata.len = length;
    metadata.stride = length;
    metadata.ecn = None;
    metadata.dst_ip = None;
    Ok(())
}

impl AsyncUdpSocket for ObfsUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SendPoller {
            io: self.io.clone(),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let segment = transmit
            .segment_size
            .filter(|size| *size > 0)
            .unwrap_or(transmit.contents.len().max(1));
        for chunk in transmit.contents.chunks(segment) {
            match &self.mode {
                None => self.send_wire(chunk, transmit.destination)?,
                Some(ObfsMode::Salamander(password)) => {
                    let wire = obfs::seal(password, chunk)?;
                    self.send_wire(&wire, transmit.destination)?;
                }
                Some(ObfsMode::Gecko {
                    password,
                    min_packet_size,
                    max_packet_size,
                }) => {
                    if gecko::should_fragment(chunk) {
                        let message_id = self.fragment_id.fetch_add(1, Ordering::Relaxed);
                        let mut random = |buffer: &mut [u8]| {
                            let _ = aws_lc_rs::rand::fill(buffer);
                        };
                        let frames = gecko::fragment(
                            chunk,
                            *min_packet_size,
                            *max_packet_size,
                            message_id,
                            obfs::SALT_LEN,
                            &mut random,
                        )?;
                        for frame in frames {
                            let wire = obfs::seal(password, &frame)?;
                            self.send_wire(&wire, transmit.destination)?;
                        }
                    } else {
                        let wire = obfs::seal(password, chunk)?;
                        self.send_wire(&wire, transmit.destination)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(buffer) = bufs.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        let Some(metadata) = meta.first_mut() else {
            return Poll::Ready(Ok(0));
        };
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            match &self.mode {
                None => match self.io.try_recv_from(&mut *buffer) {
                    Ok((length, address)) => {
                        set_meta(metadata, address, length)?;
                        return Poll::Ready(Ok(1));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Poll::Ready(Err(error)),
                },
                Some(ObfsMode::Salamander(password)) => {
                    let mut scratch = recover(self.scratch.lock());
                    match self.io.try_recv_from(scratch.as_mut_slice()) {
                        Ok((length, address)) => {
                            // 过短报文是无效 obfs 数据；丢弃并继续等待下一个报文。
                            let plain_length = match obfs::open_into(
                                password,
                                scratch.as_slice().get(..length).unwrap_or_default(),
                                &mut *buffer,
                            ) {
                                Ok(plain) => plain.len(),
                                Err(_) => continue,
                            };
                            set_meta(metadata, address, plain_length)?;
                            return Poll::Ready(Ok(1));
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
                Some(ObfsMode::Gecko { password, .. }) => {
                    let mut scratch = recover(self.scratch.lock());
                    let (length, address) = match self.io.try_recv_from(scratch.as_mut_slice()) {
                        Ok(value) => value,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(error) => return Poll::Ready(Err(error)),
                    };
                    let mut plain = recover(self.plain.lock());
                    let plain = match obfs::open_into(
                        password,
                        scratch.as_slice().get(..length).unwrap_or_default(),
                        plain.as_mut_slice(),
                    ) {
                        Ok(plain) => plain,
                        Err(_) => continue,
                    };
                    if gecko::should_fragment(plain) {
                        let mut reassembler = recover(self.reassembler.lock());
                        let Some(packet) = reassembler.accept(address, plain, Instant::now())
                        else {
                            continue;
                        };
                        if packet.len() > buffer.len() || packet.len() > SCRATCH_LEN {
                            continue;
                        }
                        buffer[..packet.len()].copy_from_slice(&packet);
                        set_meta(metadata, address, packet.len())?;
                    } else {
                        let length = plain.len();
                        if length > buffer.len() {
                            continue;
                        }
                        buffer[..length].copy_from_slice(plain);
                        set_meta(metadata, address, length)?;
                    }
                    return Poll::Ready(Ok(1));
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

struct SendPoller {
    io: Arc<UdpSocket>,
}

impl fmt::Debug for SendPoller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SendPoller").finish()
    }
}

impl UdpPoller for SendPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io.poll_send_ready(cx)
    }
}
