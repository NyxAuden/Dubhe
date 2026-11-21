//! 单 Server 共享的精确 REALITY 重放池；不得按入口新建或在失败/取消时删除占位。
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashSet},
    io,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

// 同一静态公钥各入口的最大窗口由 bind 汇总，传入 2 * max_window + 1000ms。
const MAX_TTL: Duration = Duration::from_millis(1_201_000);
type Key = ([u8; 32], [u8; 32]);

#[derive(Default)]
struct State {
    keys: HashSet<Key>,
    expiry: BinaryHeap<Reverse<(Instant, Key)>>,
    clock: Option<(Duration, Instant)>,
}

pub(crate) struct ReplayPool {
    capacity: usize,
    state: Mutex<State>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn wall_now() -> io::Result<Duration> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("REALITY 系统时间无效"))
}

impl State {
    fn time(&mut self, wall: Duration, instant: Instant) -> io::Result<Duration> {
        let effective = if let Some((previous, anchor)) = self.clock {
            let elapsed = instant
                .checked_duration_since(anchor)
                .ok_or_else(|| invalid("REALITY 单调时钟无效"))?;
            wall.max(
                previous
                    .checked_add(elapsed)
                    .ok_or_else(|| invalid("REALITY 有效时间溢出"))?,
            )
        } else {
            wall
        };
        // auth 的有效时间范围为非负 u64 毫秒，保留完整亚秒不截断累积。
        if effective.as_millis() > u128::from(u64::MAX) {
            return Err(invalid("REALITY 有效时间超出范围"));
        }
        self.clock = Some((effective, instant));
        Ok(effective)
    }

    fn insert(
        &mut self,
        key: Key,
        ttl: Duration,
        instant: Instant,
        capacity: usize,
    ) -> io::Result<()> {
        if ttl.is_zero() || ttl > MAX_TTL {
            return Err(invalid("REALITY 重放期限无效"));
        }
        let deadline = instant
            .checked_add(ttl)
            .ok_or_else(|| invalid("REALITY 重放期限溢出"))?;
        // 到期仅依赖单调时间。墙钟跳跃不提前驱逐，回退不恢复旧有效窗口。
        while self
            .expiry
            .peek()
            .is_some_and(|Reverse((expiry, _))| *expiry <= instant)
        {
            let Reverse((_, expired)) = self.expiry.pop().expect("已检查到期项");
            self.keys.remove(&expired);
        }
        if self.keys.contains(&key) {
            return Err(invalid("REALITY 请求重放"));
        }
        if self.keys.len() >= capacity {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "REALITY 重放预算已满",
            ));
        }
        // 一有效 key 仅一堆项；重复与满额均不续期、不增墓碑、不驱逐。
        self.keys.insert(key);
        self.expiry.push(Reverse((deadline, key)));
        Ok(())
    }
}

impl ReplayPool {
    pub(crate) fn new(capacity: usize) -> io::Result<Self> {
        if !(1..=1_048_576).contains(&capacity) {
            return Err(invalid("REALITY 重放容量无效"));
        }
        Ok(Self {
            capacity,
            state: Mutex::new(State::default()),
        })
    }

    /// 返回 Unix 有效时间，由实际墙钟与上次有效时间加单调经过时间取 max。
    pub(crate) fn now(&self) -> io::Result<Duration> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("REALITY 重放状态不可用"))?;
        // 在锁内采样，避免并发线程先采样后排队而被误判单调回退。
        state.time(wall_now()?, Instant::now())
    }

    /// 仅在结构、认证和策略都通过之后调用；错误必须关闭，不得进入 fallback。
    /// public 为派生静态公钥，digest 为含密文 SID 的完整 raw ClientHello SHA256。
    pub(crate) fn insert(
        &self,
        public: [u8; 32],
        digest: [u8; 32],
        ttl: Duration,
    ) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("REALITY 重放状态不可用"))?;
        let wall = wall_now()?;
        let instant = Instant::now();
        state.time(wall, instant)?;
        state.insert((public, digest), ttl, instant, self.capacity)
    }

    #[cfg(test)]
    fn now_at(&self, wall: Duration, instant: Instant) -> io::Result<Duration> {
        self.state.lock().unwrap().time(wall, instant)
    }

    #[cfg(test)]
    fn insert_at(
        &self,
        key: Key,
        ttl: Duration,
        wall: Duration,
        instant: Instant,
    ) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.time(wall, instant)?;
        state.insert(key, ttl, instant, self.capacity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    };
    const TTL: Duration = Duration::from_millis(241_000);
    fn key(n: u8) -> Key {
        ([1; 32], [n; 32])
    }
    fn wall() -> Duration {
        Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn capacity_one_full_duplicate_expiry_and_no_tombstones() {
        let pool = ReplayPool::new(1).unwrap();
        let start = Instant::now();
        pool.insert_at(key(1), TTL, wall(), start).unwrap();
        for _ in 0..1000 {
            assert_eq!(
                pool.insert_at(key(1), TTL, wall(), start)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                pool.insert_at(key(2), TTL, wall(), start)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
        }
        assert_eq!(
            {
                let state = pool.state.lock().unwrap();
                (state.keys.len(), state.expiry.len())
            },
            (1, 1)
        );
        assert!(
            pool.insert_at(key(1), TTL, wall(), start + TTL - Duration::from_nanos(1))
                .is_err()
        );
        pool.insert_at(key(2), TTL, wall(), start + TTL).unwrap();
        assert_eq!(
            {
                let state = pool.state.lock().unwrap();
                (state.keys.len(), state.expiry.len())
            },
            (1, 1)
        );
        // 重复不续期；第二条按自己的原始期限准确到期。
        assert!(
            pool.insert_at(key(2), TTL, wall(), start + TTL + Duration::from_secs(1))
                .is_err()
        );
        pool.insert_at(key(2), TTL, wall(), start + TTL * 2)
            .unwrap();
    }

    #[test]
    fn equivalent_private_encodings_cannot_bypass_public_namespace() {
        use aws_lc_rs::agreement::{PrivateKey, X25519};
        let first = [7; 32];
        let mut second = first;
        second[0] ^= 7;
        second[31] ^= 0x80;
        let public = |raw: &[u8; 32]| -> [u8; 32] {
            PrivateKey::from_private_key(&X25519, raw)
                .unwrap()
                .compute_public_key()
                .unwrap()
                .as_ref()
                .try_into()
                .unwrap()
        };
        let pool = ReplayPool::new(2).unwrap();
        let now = Instant::now();
        let a = public(&first);
        let b = public(&second);
        assert_eq!(a, b);
        pool.insert_at((a, [9; 32]), TTL, wall(), now).unwrap();
        assert!(pool.insert_at((b, [9; 32]), TTL, wall(), now).is_err());
        assert_eq!(pool.state.lock().unwrap().keys.len(), 1);
    }

    #[test]
    fn shared_public_namespace_max_window_and_different_identity() {
        let pool = ReplayPool::new(3).unwrap();
        let now = Instant::now();
        // 模拟 bind 为同 public 的 1ms/600000ms 入口统一传入最大 TTL。
        let ttl = Duration::from_millis(2 * 600_000 + 1000);
        pool.insert_at(key(1), ttl, wall(), now).unwrap();
        assert!(
            pool.insert_at(key(1), ttl, wall(), now + Duration::from_millis(1002))
                .is_err()
        );
        pool.insert_at(
            ([2; 32], [1; 32]),
            ttl,
            wall(),
            now + Duration::from_millis(1002),
        )
        .unwrap();
        pool.insert_at(key(2), ttl, wall(), now + Duration::from_millis(1002))
            .unwrap();
        assert_eq!(pool.state.lock().unwrap().keys.len(), 3);
        pool.insert_at(key(1), ttl, wall(), now + ttl).unwrap();
    }

    #[test]
    fn concurrent_arc_entrypoints_allow_one_and_no_target_after_error() {
        let pool = Arc::new(ReplayPool::new(1).unwrap());
        let gate = Arc::new(Barrier::new(16));
        let targets = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let pool = pool.clone();
                let gate = gate.clone();
                let targets = targets.clone();
                scope.spawn(move || {
                    gate.wait();
                    if pool.insert([1; 32], [2; 32], TTL).is_ok() {
                        targets.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(targets.load(Ordering::SeqCst), 1);
        assert!(pool.insert([1; 32], [3; 32], TTL).is_err());
        assert_eq!(
            {
                let state = pool.state.lock().unwrap();
                (state.keys.len(), state.expiry.len())
            },
            (1, 1)
        );
    }

    #[tokio::test]
    async fn cancellation_keeps_committed_key_and_unauthenticated_input_uses_no_capacity() {
        let pool = Arc::new(ReplayPool::new(1).unwrap());
        // 未经过 insert 的普通/未认证输入不消耗任何占位。
        for _ in 0..128 {
            pool.now().unwrap();
        }
        assert!(pool.state.lock().unwrap().keys.is_empty());
        let (ready, received) = tokio::sync::oneshot::channel();
        let other = pool.clone();
        let task = tokio::spawn(async move {
            other.insert([1; 32], [2; 32], TTL).unwrap();
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        received.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(pool.insert([1; 32], [2; 32], TTL).is_err());
        assert_eq!(pool.state.lock().unwrap().expiry.len(), 1);
    }

    #[test]
    fn subsecond_clock_backward_wall_and_forward_jump_remain_monotonic() {
        let pool = ReplayPool::new(1).unwrap();
        let start = Instant::now();
        let initial = wall() + Duration::from_micros(123456);
        assert_eq!(pool.now_at(initial, start).unwrap(), initial);
        for n in 1..=100 {
            let elapsed = Duration::from_micros(n * 123);
            assert_eq!(
                pool.now_at(wall() - Duration::from_secs(10), start + elapsed)
                    .unwrap(),
                initial + elapsed
            );
        }
        let jump = wall() + Duration::from_secs(1_000_000);
        assert_eq!(
            pool.now_at(jump, start + Duration::from_secs(1)).unwrap(),
            jump
        );
        assert_eq!(
            pool.now_at(wall(), start + Duration::from_millis(1001))
                .unwrap(),
            jump + Duration::from_millis(1)
        );
        assert!(pool.now_at(wall(), start).is_err());
        assert_eq!(
            pool.now_at(wall(), start + Duration::from_millis(1002))
                .unwrap(),
            jump + Duration::from_millis(2)
        );
    }

    #[test]
    fn wall_jump_never_evicts_early_and_clock_overflow_fails_closed() {
        let pool = ReplayPool::new(1).unwrap();
        let now = Instant::now();
        pool.insert_at(key(1), TTL, wall(), now).unwrap();
        assert!(
            pool.insert_at(
                key(2),
                TTL,
                wall() + Duration::from_secs(10_000),
                now + Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            pool.insert_at(
                key(2),
                TTL,
                wall() - Duration::from_secs(10_000),
                now + Duration::from_secs(2)
            )
            .is_err()
        );
        assert_eq!(pool.state.lock().unwrap().expiry.len(), 1);
        assert!(
            pool.now_at(Duration::MAX, now + Duration::from_secs(3))
                .is_err()
        );
        assert!(
            pool.insert_at(key(2), Duration::ZERO, wall(), now + Duration::from_secs(4))
                .is_err()
        );
        assert!(
            pool.insert_at(key(2), Duration::MAX, wall(), now + Duration::from_secs(5))
                .is_err()
        );
        assert_eq!(pool.state.lock().unwrap().keys.len(), 1);
        let extreme = ReplayPool::new(1).unwrap();
        let last = Duration::from_millis(u64::MAX);
        extreme.now_at(last, now).unwrap();
        assert!(
            extreme
                .now_at(last, now + Duration::from_millis(1))
                .is_err()
        );
        assert!(ReplayPool::new(0).is_err());
        assert!(ReplayPool::new(1048577).is_err());
    }
}
