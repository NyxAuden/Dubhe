//! VMess 两类精确标识共享有限容量；单调保护期覆盖全部 AuthID 有效窗口。
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashSet},
    io,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

const TTL: Duration = Duration::from_secs(241);
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Kind {
    Auth([u8; 16]),
    Session([u8; 32]),
}
type Key = ([u8; 16], Kind);
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
impl ReplayPool {
    pub(crate) fn new(capacity: usize) -> Self {
        assert!((1..=1048576).contains(&capacity));
        Self {
            capacity,
            state: Mutex::new(State::default()),
        }
    }
    pub(crate) fn now(&self) -> io::Result<u64> {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid("VMess 系统时间无效"))?;
        self.now_at(wall, Instant::now())
    }
    fn now_at(&self, wall: Duration, instant: Instant) -> io::Result<u64> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("VMess 重放状态不可用"))?;
        let effective = if let Some((previous, anchor)) = state.clock {
            let delta = instant
                .checked_duration_since(anchor)
                .ok_or_else(|| invalid("VMess 单调时钟无效"))?;
            wall.max(
                previous
                    .checked_add(delta)
                    .ok_or_else(|| invalid("VMess 时间溢出"))?,
            )
        } else {
            wall
        };
        if effective.as_secs() > i64::MAX as u64 {
            return Err(invalid("VMess 时间超出范围"));
        }
        state.clock = Some((effective, instant));
        Ok(effective.as_secs())
    }
    pub(crate) fn auth(
        &self,
        uuid: [u8; 16],
        id: [u8; 16],
        timestamp: u64,
        now: u64,
    ) -> io::Result<()> {
        if timestamp > i64::MAX as u64 || timestamp.abs_diff(now) > 120 {
            return Err(invalid("VMess 认证时间无效"));
        }
        self.insert((uuid, Kind::Auth(id)), Instant::now())
    }
    pub(crate) fn session(&self, uuid: [u8; 16], key: [u8; 16], iv: [u8; 16]) -> io::Result<()> {
        let mut material = [0; 32];
        material[..16].copy_from_slice(&key);
        material[16..].copy_from_slice(&iv);
        self.insert((uuid, Kind::Session(material)), Instant::now())
    }
    fn insert(&self, key: Key, now: Instant) -> io::Result<()> {
        let deadline = now
            .checked_add(TTL)
            .ok_or_else(|| invalid("VMess 保护期限溢出"))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("VMess 重放状态不可用"))?;
        while state
            .expiry
            .peek()
            .is_some_and(|Reverse((deadline, _))| *deadline <= now)
        {
            let Reverse((_, expired)) = state.expiry.pop().expect("已检查");
            state.keys.remove(&expired);
        }
        if state.keys.contains(&key) {
            return Err(invalid("VMess 请求重放"));
        }
        if state.keys.len() >= self.capacity {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "VMess 重放预算已满",
            ));
        }
        state.keys.insert(key);
        state.expiry.push(Reverse((deadline, key)));
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_capacity_exact_expiry_and_no_stale_items() {
        let p = ReplayPool::new(2);
        let now = Instant::now();
        let a = ([1; 16], Kind::Auth([2; 16]));
        p.insert(a, now).unwrap();
        p.session([1; 16], [3; 16], [4; 16]).unwrap();
        for _ in 0..8 {
            assert!(p.insert(a, now).is_err());
            assert!(p.insert(([5; 16], Kind::Auth([6; 16])), now).is_err());
        }
        let s = p.state.lock().unwrap();
        assert_eq!((s.keys.len(), s.expiry.len()), (2, 2));
        drop(s);
        assert!(p.insert(a, now + Duration::from_secs(240)).is_err());
        p.insert(a, now + TTL).unwrap();
    }
    #[test]
    fn clock_retains_subseconds_and_never_reopens_old_window() {
        let p = ReplayPool::new(2);
        let now = Instant::now();
        assert_eq!(p.now_at(Duration::from_secs(1000), now).unwrap(), 1000);
        for n in 1..=20 {
            assert_eq!(
                p.now_at(
                    Duration::from_secs(900),
                    now + Duration::from_millis(n * 100)
                )
                .unwrap(),
                1000 + n / 10
            );
        }
        assert_eq!(
            p.now_at(Duration::from_secs(2000), now + Duration::from_secs(3))
                .unwrap(),
            2000
        );
        assert_eq!(
            p.now_at(Duration::from_secs(1000), now + Duration::from_secs(4))
                .unwrap(),
            2001
        );
        assert!(
            p.now_at(Duration::MAX, now + Duration::from_secs(5))
                .is_err()
        );
    }
    #[test]
    fn time_bounds_identity_and_session_reuse() {
        let p = ReplayPool::new(8);
        p.auth([1; 16], [2; 16], 1120, 1000).unwrap();
        assert!(p.auth([1; 16], [2; 16], 1120, 1000).is_err());
        p.auth([3; 16], [2; 16], 1120, 1000).unwrap();
        assert!(p.auth([1; 16], [4; 16], 1121, 1000).is_err());
        assert!(p.auth([1; 16], [4; 16], u64::MAX, 1000).is_err());
        p.session([1; 16], [5; 16], [6; 16]).unwrap();
        assert!(p.session([1; 16], [5; 16], [6; 16]).is_err());
    }
    #[test]
    fn concurrent_saturation_never_exceeds_capacity_or_adds_heap_tombstones() {
        let p = std::sync::Arc::new(ReplayPool::new(3));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|n| {
                let p = p.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    p.auth([1; 16], [n; 16], 1000, 1000).is_ok()
                })
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .filter_map(|t| t.join().unwrap().then_some(()))
                .count(),
            3
        );
        let state = p.state.lock().unwrap();
        assert_eq!((state.keys.len(), state.expiry.len()), (3, 3));
    }

    #[test]
    fn future_id_is_held_through_last_valid_second_and_clock_error_does_not_reanchor() {
        let p = ReplayPool::new(1);
        let start = Instant::now();
        let identity = ([1; 16], Kind::Auth([2; 16]));
        assert_eq!(p.now_at(Duration::from_secs(1000), start).unwrap(), 1000);
        p.insert(identity, start).unwrap();
        // 初见允许未来120秒，至240.999秒仍在整数秒的有效窗内。
        let last = start + Duration::from_millis(240_999);
        assert_eq!(p.now_at(Duration::from_secs(900), last).unwrap(), 1240);
        assert!(p.insert(identity, last).is_err());
        assert!(p.now_at(Duration::from_secs(900), start).is_err());
        assert!(
            p.now_at(Duration::MAX, last + Duration::from_nanos(1))
                .is_err()
        );
        assert_eq!(
            p.now_at(Duration::from_secs(900), start + TTL).unwrap(),
            1241
        );
        p.insert(identity, start + TTL).unwrap();
        let state = p.state.lock().unwrap();
        assert_eq!((state.keys.len(), state.expiry.len()), (1, 1));
    }

    #[test]
    fn concurrent_duplicates_admit_once() {
        let p = std::sync::Arc::new(ReplayPool::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let p = p.clone();
                std::thread::spawn(move || p.auth([1; 16], [2; 16], 1000, 1000).is_ok())
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .filter_map(|t| t.join().unwrap().then_some(()))
                .count(),
            1
        );
    }
}
