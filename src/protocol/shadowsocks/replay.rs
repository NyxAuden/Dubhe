//! 精确salt准入：共享同入口/身份的收发和协议路径，容量满时不驱逐保护记录。
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashSet},
    io,
    sync::Mutex,
    time::Duration,
};

use tokio::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Domain {
    pub inbound: usize,
    pub identity: usize,
}

#[derive(Clone, Copy)]
pub(crate) enum Window {
    Aead2017,
    Aead2022,
}

impl Window {
    fn duration(self) -> Duration {
        Duration::from_secs(match self {
            Self::Aead2017 => 120,
            Self::Aead2022 => 60,
        })
    }
}

// 固定存储，不让请求长度控制记录大小；刻意不实现Debug，避免打印salt。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Salt {
    bytes: [u8; 32],
    length: u8,
}

impl Salt {
    fn new(input: &[u8]) -> io::Result<Self> {
        if !matches!(input.len(), 16 | 32) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "salt长度无效"));
        }
        let mut salt = Self {
            bytes: [0; 32],
            length: input.len() as u8,
        };
        salt.bytes[..input.len()].copy_from_slice(input);
        Ok(salt)
    }
}

type Key = (Domain, Salt);

#[derive(Default)]
struct State {
    keys: HashSet<Key>,
    // 每条有效记录恰有一个到期项；重复/容量失败不追加，绝无陈旧队列增长。
    expiry: BinaryHeap<Reverse<(Instant, Key)>>,
}

pub(crate) struct ReplayPool {
    capacity: usize,
    state: Mutex<State>,
}

impl ReplayPool {
    pub(crate) fn new(capacity: usize) -> Self {
        assert!((1..=1_048_576).contains(&capacity));
        Self {
            capacity,
            state: Mutex::new(State::default()),
        }
    }

    pub(crate) fn admit(&self, domain: Domain, salt: &[u8], window: Window) -> io::Result<()> {
        self.admit_at(domain, salt, window, Instant::now())
    }

    fn admit_at(
        &self,
        domain: Domain,
        salt: &[u8],
        window: Window,
        now: Instant,
    ) -> io::Result<()> {
        let key = (domain, Salt::new(salt)?);
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("重放池状态不可用"))?;
        while state
            .expiry
            .peek()
            .is_some_and(|Reverse((deadline, _))| *deadline <= now)
        {
            let Reverse((_, expired)) = state.expiry.pop().expect("到期项已检查");
            state.keys.remove(&expired);
        }
        if state.keys.contains(&key) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "重复salt"));
        }
        if state.keys.len() >= self.capacity {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "重放池容量已满"));
        }
        state.keys.insert(key);
        state.expiry.push(Reverse((now + window.duration(), key)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    const DOMAIN: Domain = Domain {
        inbound: 0,
        identity: 0,
    };

    fn sizes(pool: &ReplayPool) -> (usize, usize) {
        let state = pool.state.lock().unwrap();
        (state.keys.len(), state.expiry.len())
    }

    #[test]
    fn mixed_windows_expire_by_deadline_not_insertion_order() {
        let pool = ReplayPool::new(2);
        let now = Instant::now();
        pool.admit_at(DOMAIN, &[1; 16], Window::Aead2017, now)
            .unwrap();
        pool.admit_at(DOMAIN, &[2; 16], Window::Aead2022, now)
            .unwrap();
        assert_eq!(
            pool.admit_at(
                DOMAIN,
                &[3; 16],
                Window::Aead2022,
                now + Duration::from_secs(59)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::WouldBlock
        );
        // 后插入的60秒记录先释放，120秒记录不能被容量驱逐。
        pool.admit_at(
            DOMAIN,
            &[3; 16],
            Window::Aead2022,
            now + Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(
            pool.admit_at(
                DOMAIN,
                &[1; 16],
                Window::Aead2017,
                now + Duration::from_secs(119)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        pool.admit_at(
            DOMAIN,
            &[1; 16],
            Window::Aead2017,
            now + Duration::from_secs(120),
        )
        .unwrap();
        assert_eq!(sizes(&pool), (1, 1));
    }

    #[test]
    fn scope_separates_inbounds_identities_and_salt_lengths() {
        let pool = ReplayPool::new(4);
        for domain in [
            DOMAIN,
            Domain {
                inbound: 1,
                ..DOMAIN
            },
            Domain {
                identity: 1,
                ..DOMAIN
            },
        ] {
            pool.admit(domain, &[1; 16], Window::Aead2017).unwrap();
        }
        pool.admit(DOMAIN, &[1; 32], Window::Aead2022).unwrap();
        assert_eq!(sizes(&pool), (4, 4));
        // 不区分收发或TCP/UDP，同一域/同一salt只能准入一次。
        assert_eq!(
            pool.admit(DOMAIN, &[1; 16], Window::Aead2022)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(pool.admit(DOMAIN, &[1; 15], Window::Aead2017).is_err());
        assert_eq!(sizes(&pool), (4, 4));
    }

    #[test]
    fn concurrent_duplicate_has_exactly_one_winner() {
        let pool = Arc::new(ReplayPool::new(16));
        let barrier = Arc::new(Barrier::new(16));
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    let pool = pool.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        pool.admit(DOMAIN, &[7; 32], Window::Aead2022).is_ok()
                    })
                })
                .collect();
            let winners = handles
                .into_iter()
                .map(|handle| usize::from(handle.join().unwrap()))
                .sum::<usize>();
            assert_eq!(winners, 1);
        });
        // 上面线程作用域等待全部结束，记录数也必须只有一条。
        assert_eq!(sizes(&pool), (1, 1));
    }

    #[test]
    fn failures_and_expiry_never_accumulate_stale_queue_entries() {
        let pool = ReplayPool::new(1);
        let start = Instant::now();
        for cycle in 0..2048u64 {
            let now = start + Duration::from_secs(cycle * 120);
            pool.admit_at(DOMAIN, &[1; 16], Window::Aead2017, now)
                .unwrap();
            for _ in 0..4 {
                assert!(
                    pool.admit_at(DOMAIN, &[1; 16], Window::Aead2017, now)
                        .is_err()
                );
                assert!(
                    pool.admit_at(DOMAIN, &[2; 16], Window::Aead2017, now)
                        .is_err()
                );
            }
            assert_eq!(sizes(&pool), (1, 1));
        }
    }
}
