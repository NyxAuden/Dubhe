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
pub struct UserCounters {
    uplink: AtomicU64,
    downlink: AtomicU64,
    /// 计数起点（unix 毫秒）。`reset` 时更新，用于告诉面板「这个数字从什么时候开始算」。
    since_ms: AtomicU64,
    /// 配额上限（字节）；`0` 表示不限制。超限后拒绝**新连接**，不断开已有连接。
    quota_bytes: AtomicU64,
    /// 到期时间（unix 毫秒）；`0` 表示不过期。
    expires_at_ms: AtomicU64,
}

impl Default for UserCounters {
    fn default() -> Self {
        Self {
            uplink: AtomicU64::new(0),
            downlink: AtomicU64::new(0),
            since_ms: AtomicU64::new(now_ms()),
            quota_bytes: AtomicU64::new(0),
            expires_at_ms: AtomicU64::new(0),
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

impl UserCounters {
    /// 计入一批业务字节。
    ///
    /// 公开是因为 `tests/mux_cool.rs` 以 `#[path]` 方式把 `src/mux.rs` 编进
    /// 测试 crate，那里的 `pub(crate)` 指向测试 crate 自己。
    pub fn add(&self, uplink: bool, bytes: usize) {
        let counter = if uplink { &self.uplink } else { &self.downlink };
        counter.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn uplink(&self) -> u64 {
        self.uplink.load(Ordering::Relaxed)
    }

    pub fn downlink(&self) -> u64 {
        self.downlink.load(Ordering::Relaxed)
    }

    pub fn since_ms(&self) -> u64 {
        self.since_ms.load(Ordering::Relaxed)
    }

    /// 清零累计字节并把计数起点移到当前时刻。
    ///
    /// 与并发累加有极小竞态（`store` 与 `fetch_add` 之间到达的字节可能丢失），
    /// 这与 Xray 的 `StatsService` 语义一致：重置是运维动作，不追求逐字节精确。
    pub fn reset(&self) {
        self.uplink.store(0, Ordering::Relaxed);
        self.downlink.store(0, Ordering::Relaxed);
        self.since_ms.store(now_ms(), Ordering::Relaxed);
    }

    pub fn set_quota(&self, bytes: u64) {
        self.quota_bytes.store(bytes, Ordering::Relaxed);
    }

    pub fn set_expires_at(&self, at_ms: u64) {
        self.expires_at_ms.store(at_ms, Ordering::Relaxed);
    }

    /// 该用户是否仍允许建立新连接。
    ///
    /// 只检查「到期」与「累计用量」，**不断开已建立的连接**：与 Xray/sing-box
    /// 一致，配额是准入控制而不是强制中断。
    pub fn admits_new_connection(&self) -> bool {
        let expires = self.expires_at_ms.load(Ordering::Relaxed);
        if expires != 0 && now_ms() >= expires {
            return false;
        }
        let quota = self.quota_bytes.load(Ordering::Relaxed);
        if quota != 0 {
            let used = self.uplink() + self.downlink();
            if used >= quota {
                return false;
            }
        }
        true
    }
}

/// 管理接口返回的单用户快照。
#[derive(Debug, Serialize)]
pub struct UserSnapshot {
    pub inbound: String,
    pub user: String,
    pub uplink: u64,
    pub downlink: u64,
    /// 计数起点（unix 毫秒）。`reset` 会更新它，面板据此判断「这个数字算的是哪一段」。
    pub since_ms: u64,
    /// 配额上限（字节）；`0` 表示不限制。
    pub quota_bytes: u64,
    /// 到期时间（unix 毫秒）；`0` 表示不过期。
    pub expires_at_ms: u64,
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
                since_ms: counter.since_ms(),
                quota_bytes: counter.quota_bytes.load(Ordering::Relaxed),
                expires_at_ms: counter.expires_at_ms.load(Ordering::Relaxed),
            })
            .collect();
        items.sort_by(|left, right| {
            left.inbound
                .cmp(&right.inbound)
                .then_with(|| left.user.cmp(&right.user))
        });
        items
    }

    /// 清零用户计数。`inbound` 与 `user` 均为 `None` 时清空全部。
    ///
    /// 返回被清零的条目数。用于面板的「重置流量」动作——此前只有只读的
    /// `GET /stats/users`，计数只能等进程重启才归零。
    pub fn reset_users(&self, inbound: Option<&str>, user: Option<&str>) -> usize {
        let users = self.users.read().unwrap_or_else(|error| error.into_inner());
        let mut count = 0;
        for ((entry_inbound, entry_user), counter) in users.iter() {
            if inbound.is_some_and(|value| value != entry_inbound) {
                continue;
            }
            if user.is_some_and(|value| value != entry_user) {
                continue;
            }
            counter.reset();
            count += 1;
        }
        count
    }

    /// 设置某个用户（或全部匹配项）的配额与到期时间。
    pub fn set_user_limits(
        &self,
        inbound: Option<&str>,
        user: Option<&str>,
        quota_bytes: Option<u64>,
        expires_at_ms: Option<u64>,
    ) -> usize {
        let users = self.users.read().unwrap_or_else(|error| error.into_inner());
        let mut count = 0;
        for ((entry_inbound, entry_user), counter) in users.iter() {
            if inbound.is_some_and(|value| value != entry_inbound) {
                continue;
            }
            if user.is_some_and(|value| value != entry_user) {
                continue;
            }
            if let Some(quota) = quota_bytes {
                counter.set_quota(quota);
            }
            if let Some(expires) = expires_at_ms {
                counter.set_expires_at(expires);
            }
            count += 1;
        }
        count
    }

    /// 包裹客户端流：读入算上行、写出算下行。`None` 表示该路径暂不归因。
    /// 准入检查：该用户当前是否允许建立新连接。
    ///
    /// 只检查配额与到期，**不断开已建立的连接**。作为准入控制而不是强制中断，
    /// 与 Xray/Sing-box 把「策略」留给面板的做法一致；区别是内核能直接拒绝，
    /// 面板不必再拉一层。
    pub fn admit_user(&self, inbound: &str, user: Option<&str>) -> bool {
        let Some(user) = user else {
            return true;
        };
        let users = self.users.read().unwrap_or_else(|error| error.into_inner());
        users
            .get(&(inbound.to_owned(), user.to_owned()))
            .is_none_or(|counter| counter.admits_new_connection())
    }

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
    /// 批量计入 rejected；供周期性采样合并外部计数器（如 WireGuard）使用。
    pub fn reject_many(&self, count: u64) {
        if count > 0 {
            self.rejected.fetch_add(count, Ordering::Relaxed);
        }
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
