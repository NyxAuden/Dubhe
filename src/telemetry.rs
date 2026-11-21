use std::{
    collections::HashMap,
    fmt::Write as _,
    io,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
pub struct Stats {
    pub connections: AtomicUsize,
    pub tcp_flows: AtomicUsize,
    pub udp_associations: AtomicUsize,
    pub grpc_streams: AtomicUsize,
    pub xhttp_sessions: AtomicUsize,
    pub uplink: AtomicU64,
    pub downlink: AtomicU64,
    pub dropped: AtomicU64,
    pub rejected: AtomicU64,
    /// TCP 中继的双向空闲超时（毫秒）；`0` 表示不限制。
    /// 对齐 Xray `policy.levels.*.connIdle`（默认 300 秒）。
    pub idle_timeout_ms: AtomicU64,
    /// 按 (入口 tag, 用户标识) 归集的业务载荷字节；未认证入口不产生条目。
    users: RwLock<HashMap<(String, String), Arc<UserCounters>>>,
}

/// 单个用户的累计字节。只统计已接入归因的协议路径。
#[derive(Default)]
pub struct UserCounters {
    uplink: AtomicU64,
    downlink: AtomicU64,
}

impl UserCounters {
    pub(crate) fn add(&self, uplink: bool, bytes: usize) {
        let counter = if uplink { &self.uplink } else { &self.downlink };
        counter.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn uplink(&self) -> u64 {
        self.uplink.load(Ordering::Relaxed)
    }

    pub fn downlink(&self) -> u64 {
        self.downlink.load(Ordering::Relaxed)
    }
}

/// 管理接口返回的单用户快照。
#[derive(Debug, Serialize)]
pub struct UserSnapshot {
    pub inbound: String,
    pub user: String,
    pub uplink: u64,
    pub downlink: u64,
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub connections: usize,
    pub tcp_flows: usize,
    pub udp_associations: usize,
    pub grpc_streams: usize,
    pub xhttp_sessions: usize,
    pub uplink: u64,
    pub downlink: u64,
    pub dropped: u64,
    pub rejected: u64,
}

impl Snapshot {
    /// Prometheus 文本格式；不引入额外指标依赖。
    pub fn prometheus(&self) -> String {
        let mut out = String::with_capacity(1024);
        out.push_str("# HELP dubhe_up Whether the kernel is running.\n");
        out.push_str("# TYPE dubhe_up gauge\n");
        out.push_str("dubhe_up 1\n");
        out.push_str(
            "# HELP dubhe_build_info Build information.\n\
             # TYPE dubhe_build_info gauge\n",
        );
        let _ = writeln!(
            out,
            "dubhe_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );
        for (name, help, value) in [
            (
                "connections",
                "Current active connections.",
                self.connections as u64,
            ),
            (
                "tcp_flows",
                "Current active TCP flows.",
                self.tcp_flows as u64,
            ),
            (
                "udp_associations",
                "Current active UDP associations.",
                self.udp_associations as u64,
            ),
            (
                "grpc_streams",
                "Current active gRPC streams.",
                self.grpc_streams as u64,
            ),
            (
                "xhttp_sessions",
                "Current active XHTTP sessions.",
                self.xhttp_sessions as u64,
            ),
        ] {
            let _ = writeln!(out, "# HELP dubhe_{name} {help}");
            let _ = writeln!(out, "# TYPE dubhe_{name} gauge");
            let _ = writeln!(out, "dubhe_{name} {value}");
        }
        for (name, help, value) in [
            (
                "uplink_bytes_total",
                "Business payload bytes written upstream.",
                self.uplink,
            ),
            (
                "downlink_bytes_total",
                "Business payload bytes written downstream.",
                self.downlink,
            ),
            (
                "dropped_packets_total",
                "UDP packets dropped by bounded queues.",
                self.dropped,
            ),
            (
                "rejected_total",
                "Connections or datagrams rejected by policy or limits.",
                self.rejected,
            ),
        ] {
            let _ = writeln!(out, "# HELP dubhe_{name} {help}");
            let _ = writeln!(out, "# TYPE dubhe_{name} counter");
            let _ = writeln!(out, "dubhe_{name} {value}");
        }
        out
    }
}

#[derive(Clone, Copy)]
pub enum Gauge {
    Connection,
    Tcp,
    Udp,
    Grpc,
    Xhttp,
}

pub struct Guard {
    stats: Arc<Stats>,
    gauge: Gauge,
}

impl Stats {
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            connections: self.connections.load(Ordering::Relaxed),
            tcp_flows: self.tcp_flows.load(Ordering::Relaxed),
            udp_associations: self.udp_associations.load(Ordering::Relaxed),
            grpc_streams: self.grpc_streams.load(Ordering::Relaxed),
            xhttp_sessions: self.xhttp_sessions.load(Ordering::Relaxed),
            uplink: self.uplink.load(Ordering::Relaxed),
            downlink: self.downlink.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
    pub fn prometheus(&self) -> String {
        self.snapshot().prometheus()
    }

    /// 带中继空闲超时的统计实例；测试与其它路径仍可用 `Default`。
    pub fn with_idle_timeout(idle_timeout_ms: u64) -> Self {
        let stats = Self::default();
        stats
            .idle_timeout_ms
            .store(idle_timeout_ms, Ordering::Relaxed);
        stats
    }

    /// 中继空闲超时；`None` 表示不限制。
    pub fn idle_timeout(&self) -> Option<std::time::Duration> {
        match self.idle_timeout_ms.load(Ordering::Relaxed) {
            0 => None,
            value => Some(std::time::Duration::from_millis(value)),
        }
    }
    fn gauge(&self, gauge: Gauge) -> &AtomicUsize {
        match gauge {
            Gauge::Connection => &self.connections,
            Gauge::Tcp => &self.tcp_flows,
            Gauge::Udp => &self.udp_associations,
            Gauge::Grpc => &self.grpc_streams,
            Gauge::Xhttp => &self.xhttp_sessions,
        }
    }
    pub fn enter(self: &Arc<Self>, gauge: Gauge) -> Guard {
        self.gauge(gauge).fetch_add(1, Ordering::Relaxed);
        Guard {
            stats: self.clone(),
            gauge,
        }
    }
    /// 取（或创建）某入口某用户的累计计数器。
    pub fn user_counter(self: &Arc<Self>, inbound: &str, user: &str) -> Arc<UserCounters> {
        let key = (inbound.to_owned(), user.to_owned());
        if let Ok(users) = self.users.read()
            && let Some(counter) = users.get(&key)
        {
            return counter.clone();
        }
        let mut users = self
            .users
            .write()
            .unwrap_or_else(|error| error.into_inner());
        users.entry(key).or_default().clone()
    }

    /// 按入口与用户返回累计字节；顺序按入口、用户排序，便于稳定输出。
    pub fn user_snapshots(&self) -> Vec<UserSnapshot> {
        let users = self.users.read().unwrap_or_else(|error| error.into_inner());
        let mut items: Vec<UserSnapshot> = users
            .iter()
            .map(|((inbound, user), counter)| UserSnapshot {
                inbound: inbound.clone(),
                user: user.clone(),
                uplink: counter.uplink(),
                downlink: counter.downlink(),
            })
            .collect();
        items.sort_by(|left, right| {
            left.inbound
                .cmp(&right.inbound)
                .then_with(|| left.user.cmp(&right.user))
        });
        items
    }

    /// 包裹客户端流：读入算上行、写出算下行。`None` 表示该路径暂不归因。
    pub fn count_user<S>(
        self: &Arc<Self>,
        inbound: &str,
        user: Option<&str>,
        inner: S,
    ) -> UserCounted<S> {
        UserCounted {
            inner,
            counters: user.map(|user| self.user_counter(inbound, user)),
        }
    }

    pub fn drop_packet(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
    pub fn reject(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.stats.gauge(self.gauge).fetch_sub(1, Ordering::Relaxed);
    }
}

// 按用户归因的客户端流包装：读入计上行、写出计下行。
//
// 只包裹已认证的客户端连接；`counters` 为 None 时行为与裸流一致。
pub struct UserCounted<S> {
    inner: S,
    counters: Option<Arc<UserCounters>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for UserCounted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result
            && let Some(counters) = &self.counters
        {
            counters.add(true, buf.filled().len() - before);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for UserCounted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result
            && let Some(counters) = &self.counters
        {
            counters.add(false, *n);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// 只统计实际成功写出的载荷，错误或部分写入不会被高估。
pub struct Counted<T> {
    pub inner: T,
    pub stats: Arc<Stats>,
    pub uplink: bool,
}
impl<T: AsyncRead + Unpin> AsyncRead for Counted<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Counted<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            let counter = if self.uplink {
                &self.stats.uplink
            } else {
                &self.stats.downlink
            };
            counter.fetch_add(*n as u64, Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_snapshot_has_stable_names_and_values() {
        let stats = Stats::default();
        stats.connections.store(2, Ordering::Relaxed);
        stats.udp_associations.store(3, Ordering::Relaxed);
        stats.uplink.store(17, Ordering::Relaxed);
        stats.dropped.store(5, Ordering::Relaxed);
        let text = stats.prometheus();
        assert!(text.contains("dubhe_up 1\n"), "{text}");
        assert!(text.contains("dubhe_connections 2\n"), "{text}");
        assert!(text.contains("dubhe_udp_associations 3\n"), "{text}");
        assert!(text.contains("dubhe_uplink_bytes_total 17\n"), "{text}");
        assert!(text.contains("dubhe_dropped_packets_total 5\n"), "{text}");
        assert!(
            text.contains("# TYPE dubhe_uplink_bytes_total counter\n"),
            "{text}"
        );
        let version = format!("version=\"{}\"", env!("CARGO_PKG_VERSION"));
        assert!(text.contains(&version), "{text}");
    }

    #[tokio::test]
    async fn user_counted_attributes_reads_uplink_and_writes_downlink() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, split};

        let stats = Arc::new(Stats::default());
        let (client, server) = tokio::io::duplex(64);
        let wrapped = stats.count_user("vless-in", Some("alice"), server);
        let (mut read, mut write) = split(wrapped);
        let peer = tokio::spawn(async move {
            let mut client = client;
            let mut inbound = [0u8; 8];
            client.read_exact(&mut inbound).await.unwrap();
            client.write_all(b"world!").await.unwrap();
        });
        write.write_all(b"12345678").await.unwrap();
        let mut outbound = [0u8; 6];
        read.read_exact(&mut outbound).await.unwrap();
        peer.await.unwrap();
        drop(read);
        drop(write);

        let users = stats.user_snapshots();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].inbound, "vless-in");
        assert_eq!(users[0].user, "alice");
        // 写出 8 字节给客户端 = 下行；从客户端读到 6 字节 = 上行。
        assert_eq!(users[0].downlink, 8);
        assert_eq!(users[0].uplink, 6);
    }

    #[tokio::test]
    async fn unauthenticated_paths_do_not_create_user_entries() {
        use tokio::io::AsyncWriteExt as _;

        let stats = Arc::new(Stats::default());
        let (_client, server) = tokio::io::duplex(8);
        let mut wrapped = stats.count_user("socks-in", None, server);
        wrapped.write_all(b"x").await.unwrap();
        assert!(stats.user_snapshots().is_empty());
    }
}
