//! 共享锁恢复入口。
//!
//! 本仓库的 `std::sync::Mutex` 只保护可重建的计数器、时间戳、快照与表项，
//! 不存在“半更新后不可用”的跨字段不变式。中毒后取回内部值继续使用，
//! 可以避免单个任务的 panic 放大为该监听入口的全部请求失败。

use std::sync::{Mutex, MutexGuard};

/// 取锁；若此前有任务持锁 panic，则恢复并继续使用内部值。
pub(crate) fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

/// 供 `unwrap_or_else(poisoned)` 直接使用。
pub(crate) fn poisoned<T>(error: std::sync::PoisonError<T>) -> T {
    error.into_inner()
}
