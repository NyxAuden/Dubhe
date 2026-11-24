//! 活动 TCP 连接注册表，供管理 API 列出与关闭连接。
//!
//! 只在建立上游连接时登记，`Upstream` 丢弃时自动注销；因此注册表只覆盖
//! 已经通过认证并完成路由选择的 TCP 会话，不包含 UDP 关联与 urltest 探测。
//! 连接元数据包含目标地址，管理 API 仍只允许回环监听并要求 Bearer token。

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    task::Waker,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::session::{Host, Target};

/// 管理接口返回的单条连接快照。
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Entry {
    pub id: u64,
    pub inbound: String,
    pub outbound: String,
    pub network: &'static str,
    pub host: String,
    pub port: u16,
    pub started_ms: u64,
    /// 客户端到上游的业务字节。
    pub upload: u64,
    /// 上游到客户端的业务字节。
    pub download: u64,
}

#[derive(Default)]
pub(crate) struct Registry {
    next: AtomicU64,
    /// 只持弱引用：`Upstream` 是唯一生命周期所有者，丢弃时触发注销。
    /// 若这里持 `Arc`，注册表自身会让强计数永不归零，条目永远无法移除。
    entries: Mutex<HashMap<u64, Weak<Connection>>>,
}

impl Registry {
    /// 登记一条会话；调用方把返回的 `Arc` 附加到 `Upstream` 上。
    pub(crate) fn register(
        self: &Arc<Self>,
        inbound: &str,
        outbound: &str,
        target: &Target,
    ) -> Arc<Connection> {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let connection = Arc::new(Connection {
            registry: Arc::downgrade(self),
            id,
            entry: Entry {
                id,
                inbound: inbound.to_owned(),
                outbound: outbound.to_owned(),
                network: "tcp",
                host: match &target.host {
                    Host::Ip(ip) => ip.to_string(),
                    Host::Domain(domain) => domain.clone(),
                },
                port: target.port,
                started_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_millis() as u64),
                upload: 0,
                download: 0,
            },
            close: CancellationToken::new(),
            waker: Mutex::new(None),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
        });
        self.lock().insert(id, Arc::downgrade(&connection));
        connection
    }

    pub(crate) fn snapshot(&self) -> Vec<Entry> {
        // 锁内只收集强引用，读元数据与排序都在锁外：如果连接恰好在快照期间
        // 结束，最后一个 `Arc` 会在锁内析构并触发 `Drop → registry.remove()`，
        // 那是同一把非重入锁——管理请求会把自己锁死。
        let connections: Vec<Arc<Connection>> = {
            let entries = self.lock();
            entries.values().filter_map(Weak::upgrade).collect()
        };
        let mut snapshot: Vec<Entry> = connections
            .iter()
            .map(|connection| {
                let mut entry = connection.entry.clone();
                entry.upload = connection.upload.load(Ordering::Relaxed);
                entry.download = connection.download.load(Ordering::Relaxed);
                entry
            })
            .collect();
        snapshot.sort_by_key(|entry| entry.id);
        snapshot
    }

    /// 请求关闭单条连接；返回是否命中。
    pub(crate) fn close(&self, id: u64) -> bool {
        let connection = self.lock().get(&id).and_then(Weak::upgrade);
        match connection {
            Some(connection) => {
                connection.cancel();
                true
            }
            None => false,
        }
    }

    /// 请求关闭全部连接；返回请求关闭的数量。
    pub(crate) fn close_all(&self) -> usize {
        let connections: Vec<_> = self.lock().values().filter_map(Weak::upgrade).collect();
        for connection in &connections {
            connection.cancel();
        }
        connections.len()
    }

    fn remove(&self, id: u64) {
        self.lock().remove(&id);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Weak<Connection>>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// 单条会话的关闭句柄；最后一个引用丢弃时自动注销。
pub(crate) struct Connection {
    registry: Weak<Registry>,
    id: u64,
    entry: Entry,
    close: CancellationToken,
    /// 转发任务最近一次的 waker；取消时主动唤醒，避免任务停在 socket 等待上。
    waker: Mutex<Option<Waker>>,
    upload: AtomicU64,
    download: AtomicU64,
}

impl Connection {
    /// 管理接口是否已请求关闭该连接；`Upstream` 在读写前检查。
    pub(crate) fn is_closed(&self) -> bool {
        self.close.is_cancelled()
    }

    pub(crate) fn add_upload(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn add_download(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 记录转发任务的 waker；与当前相同则跳过克隆。
    pub(crate) fn register_waker(&self, waker: &Waker) {
        let mut slot = self
            .waker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot
            .as_ref()
            .is_none_or(|current| !current.will_wake(waker))
        {
            *slot = Some(waker.clone());
        }
    }

    fn cancel(&self) {
        self.close.cancel();
        let waker = self
            .waker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.remove(self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            host: Host::Domain("example.test".into()),
            port: 443,
        }
    }

    #[test]
    fn registration_is_listed_and_removed_on_drop() {
        let registry = Arc::new(Registry::default());
        let connection = registry.register("socks", "direct", &target());
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].inbound, "socks");
        assert_eq!(snapshot[0].outbound, "direct");
        assert_eq!(snapshot[0].host, "example.test");
        assert_eq!(snapshot[0].port, 443);
        assert!(!connection.is_closed());

        let id = snapshot[0].id;
        assert!(registry.close(id));
        assert!(connection.is_closed());
        assert!(registry.close(id), "重复关闭保持幂等");
        assert_eq!(registry.snapshot().len(), 1, "关闭后等待 Upstream 丢弃");

        drop(connection);
        assert!(registry.snapshot().is_empty());
        assert!(!registry.close(id));
    }

    /// 快照与连接结束并发：不能在持锁时析构最后一个强引用。
    ///
    /// 这是真实时序竞态（升级成功 → 外部引用先释放 → `map` 里析构最后一个
    /// `Arc` → `Drop` 再取同一把锁），单次调用无法稳定命中。这里用压测把
    /// 窗口撞出来：旧实现下会自锁、测试超时，而不是断言失败。
    #[test]
    fn snapshot_never_deadlocks_while_connections_end() {
        let registry = Arc::new(Registry::default());
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut readers = Vec::new();
        for _ in 0..4 {
            let registry = registry.clone();
            let done = done.clone();
            readers.push(std::thread::spawn(move || {
                while !done.load(Ordering::Relaxed) {
                    let _ = registry.snapshot();
                }
            }));
        }
        for _ in 0..2_000 {
            let connection = registry.register("socks", "direct", &target());
            drop(connection);
        }
        done.store(true, Ordering::Relaxed);
        for reader in readers {
            reader.join().unwrap();
        }
        assert!(registry.snapshot().is_empty());
    }

    #[test]
    fn close_all_covers_every_connection() {
        let registry = Arc::new(Registry::default());
        let first = registry.register("a", "direct", &target());
        let second = registry.register("b", "socks5", &target());
        assert_eq!(registry.close_all(), 2);
        assert!(first.is_closed());
        assert!(second.is_closed());
        assert_eq!(registry.close_all(), 2, "已请求关闭但尚未注销");
    }
}
