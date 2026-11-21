//! 用户态 IP 隧道共享的固定目标 UDP socket。线上的 IP/UDP 编解码由 smoltcp
//! 完成；本层只负责端口、数据报边界、源过滤、取消安全与 socket 所有权。
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{Socket, udp},
    wire::{IpAddress, IpEndpoint, IpListenEndpoint},
};
use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

pub(crate) trait DatagramSession: Send {
    fn send<'a>(
        &'a mut self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;
    fn recv(&mut self) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + '_>>;
    fn close(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

impl DatagramSession for nowhere::VectorDatagram {
    fn send<'a>(
        &'a mut self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            match nowhere::VectorDatagram::send(self, payload).await {
                Ok(true) => Ok(()),
                Ok(false) => Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "NW3 UDP 数据报未发送",
                )),
                Err(error) => Err(io::Error::other(format!("NW3 UDP 发送失败: {error}"))),
            }
        })
    }
    fn recv(&mut self) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            nowhere::VectorDatagram::recv(self)
                .await
                .map_err(|error| io::Error::other(format!("NW3 UDP 接收失败: {error}")))?
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "NW3 UDP Flow 结束"))
        })
    }
    fn close(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move { nowhere::VectorDatagram::close(self).await })
    }
}

pub(crate) trait UdpStack: Send + Sync + 'static {
    fn with_sockets<R>(&self, action: impl FnOnce(&mut SocketSet<'static>) -> R) -> io::Result<R>;
    fn pump_udp(&self);
    fn max_ip_packet(&self) -> Option<usize> {
        None
    }
}

pub(crate) struct Session<T: UdpStack> {
    stack: Arc<T>,
    handle: SocketHandle,
    remote: SocketAddr,
    maximum: usize,
}

fn ip(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(value) => IpAddress::Ipv4(value),
        IpAddr::V6(value) => IpAddress::Ipv6(value),
    }
}

impl<T: UdpStack> Session<T> {
    pub(crate) fn open(
        stack: Arc<T>,
        local: IpAddr,
        remote: SocketAddr,
        mtu: usize,
    ) -> io::Result<Self> {
        let maximum = mtu.saturating_sub(if remote.is_ipv4() { 28 } else { 48 });
        if remote.port() == 0 || local.is_ipv4() != remote.is_ipv4() || maximum == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "隧道 UDP 目标/地址族无效",
            ));
        }
        let handle = stack.with_sockets(|sockets| {
            // 每个 UDP socket 独占端口；从实际 socket 集检查，不用会绕回碰撞的计数器。
            let port = (49_152..=65_535)
                .find(|port| {
                    !sockets.iter().any(|(_, socket)| match socket {
                        Socket::Udp(socket) => socket.endpoint().port == *port,
                        Socket::Tcp(socket) => socket
                            .local_endpoint()
                            .is_some_and(|endpoint| endpoint.port == *port),
                    })
                })
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::AddrNotAvailable, "隧道 UDP 端口耗尽")
                })?;
            let mut socket = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 65_536]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 65_536]),
            );
            socket
                .bind(IpListenEndpoint {
                    addr: Some(ip(local)),
                    port,
                })
                .map_err(|_| io::Error::new(io::ErrorKind::AddrInUse, "隧道 UDP 端口绑定失败"))?;
            Ok::<_, io::Error>(sockets.add(socket))
        })??;
        Ok(Self {
            stack,
            handle,
            remote,
            maximum,
        })
    }
}

impl<T: UdpStack> DatagramSession for Session<T> {
    fn send<'a>(
        &'a mut self,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let overhead = if self.remote.is_ipv4() { 28 } else { 48 };
            let maximum = self
                .stack
                .max_ip_packet()
                .map(|mtu| mtu.saturating_sub(overhead))
                .unwrap_or(self.maximum)
                .min(self.maximum);
            if payload.len() > maximum {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP 数据报超过当前隧道/QUIC 路径 MTU（不静默截断）",
                ));
            }
            loop {
                let sent = self.stack.with_sockets(|sockets| {
                    let socket = sockets.get_mut::<udp::Socket>(self.handle);
                    if !socket.can_send() {
                        return Ok(false);
                    }
                    socket
                        .send_slice(
                            payload,
                            IpEndpoint::new(ip(self.remote.ip()), self.remote.port()),
                        )
                        .map(|_| true)
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::WouldBlock, "隧道 UDP 发送队列已满")
                        })
                })??;
                self.stack.pump_udp();
                if sent {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
    }

    fn recv(&mut self) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            loop {
                let packet = self.stack.with_sockets(|sockets| {
                    let socket = sockets.get_mut::<udp::Socket>(self.handle);
                    if !socket.can_recv() {
                        return None;
                    }
                    match socket.recv() {
                        Ok((payload, metadata)) => {
                            if metadata.endpoint.addr == ip(self.remote.ip())
                                && metadata.endpoint.port == self.remote.port()
                            {
                                Some(payload.to_vec())
                            } else {
                                None
                            }
                        }
                        Err(_) => None,
                    }
                })?;
                self.stack.pump_udp();
                if let Some(packet) = packet {
                    return Ok(packet);
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
    }
}

impl<T: UdpStack> Drop for Session<T> {
    fn drop(&mut self) {
        let _ = self.stack.with_sockets(|sockets| {
            // smoltcp 的 SocketSet::remove 对失效句柄会 panic；析构期 panic
            // 会与在展开的 panic 叠加导致进程 abort，故先确认句柄仍存在。
            if sockets.iter().any(|(handle, _)| handle == self.handle) {
                sockets.remove(self.handle);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct Fake(Mutex<SocketSet<'static>>);
    impl UdpStack for Fake {
        fn with_sockets<R>(
            &self,
            action: impl FnOnce(&mut SocketSet<'static>) -> R,
        ) -> io::Result<R> {
            Ok(action(&mut self.0.lock().unwrap()))
        }
        fn pump_udp(&self) {}
    }
    #[tokio::test]
    async fn udp_handles_are_distinct_cancel_safe_and_drop_reclaimed() {
        let stack = Arc::new(Fake(Mutex::new(SocketSet::new(Vec::new()))));
        let mut first = Session::open(
            stack.clone(),
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2:53".parse().unwrap(),
            1280,
        )
        .unwrap();
        let second = Session::open(
            stack.clone(),
            "10.0.0.1".parse().unwrap(),
            "10.0.0.3:53".parse().unwrap(),
            1280,
        )
        .unwrap();
        assert_ne!(first.handle, second.handle);
        assert_eq!(stack.0.lock().unwrap().iter().count(), 2);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), first.recv())
                .await
                .is_err()
        );
        first.send(b"").await.unwrap();
        assert!(first.send(&vec![0; 1280]).await.is_err());
        drop(first);
        drop(second);
        assert_eq!(stack.0.lock().unwrap().iter().count(), 0);
    }
}
