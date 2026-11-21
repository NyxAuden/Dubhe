//! 2022 UDP序号状态；调用方必须在完整认证/语义验证后才提交。
const BITS: usize = 8192;

pub(crate) struct PacketWindow {
    highest: Option<u64>,
    seen: [u64; BITS / 64],
}

impl PacketWindow {
    pub(crate) fn new() -> Self {
        Self {
            highest: None,
            seen: [0; BITS / 64],
        }
    }

    pub(crate) fn accept(&mut self, packet: u64) -> bool {
        if let Some(highest) = self.highest {
            if packet <= highest {
                let distance = highest - packet;
                if distance >= BITS as u64 {
                    return false;
                }
                let bit = packet as usize % BITS;
                let mask = 1u64 << (bit % 64);
                let word = &mut self.seen[bit / 64];
                if *word & mask != 0 {
                    return false;
                }
                *word |= mask;
                return true;
            }
            let distance = packet - highest;
            if distance >= BITS as u64 {
                self.seen.fill(0);
            } else {
                // 清理滑动经过的环形位置；最多8191次且不构造溢出范围。
                for step in 1..=distance {
                    let bit = (highest + step) as usize % BITS;
                    self.seen[bit / 64] &= !(1u64 << (bit % 64));
                }
            }
        }
        self.highest = Some(packet);
        let bit = packet as usize % BITS;
        self.seen[bit / 64] |= 1u64 << (bit % 64);
        true
    }
}

pub(crate) struct SendCounter(Option<u64>);
impl SendCounter {
    pub(crate) fn new() -> Self {
        Self(Some(0))
    }
    #[cfg(test)]
    pub(crate) fn exhausted_for_test() -> Self {
        Self(None)
    }
    pub(crate) fn next(&mut self) -> Option<u64> {
        let value = self.0?;
        self.0 = value.checked_add(1);
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_window_edges_duplicates_and_out_of_order() {
        let mut window = PacketWindow::new();
        assert!(window.accept(8192));
        assert!(window.accept(1)); // 最远仍有效的位置。
        assert!(!window.accept(0));
        assert!(!window.accept(1));
        assert!(window.accept(8191));
        assert!(!window.accept(8192));
        assert!(window.accept(8193));
        assert!(!window.accept(1)); // 已移出窗口。
        assert!(window.accept(2));
        assert!(window.accept(8194));
        assert!(!window.accept(2));
    }

    #[test]
    fn large_jump_clears_old_bits_and_u64_max_never_wraps() {
        let mut window = PacketWindow::new();
        assert!(window.accept(0));
        assert!(window.accept(8192));
        assert!(window.accept(u64::MAX));
        assert!(window.accept(u64::MAX - 1));
        assert!(window.accept(u64::MAX - 8191));
        assert!(!window.accept(u64::MAX - 8192));
        assert!(!window.accept(0));
        assert!(!window.accept(u64::MAX));
    }

    #[test]
    fn ring_wraps_reuse_only_evicted_slots() {
        let mut window = PacketWindow::new();
        for packet in 0..20000 {
            assert!(window.accept(packet));
        }
        for packet in 11808..20000 {
            assert!(!window.accept(packet));
        }
        assert!(!window.accept(11807));
    }

    #[test]
    fn send_counter_uses_last_value_once_and_stays_exhausted() {
        let mut counter = SendCounter::new();
        assert_eq!(counter.next(), Some(0));
        counter.0 = Some(u64::MAX - 1);
        assert_eq!(counter.next(), Some(u64::MAX - 1));
        assert_eq!(counter.next(), Some(u64::MAX));
        assert_eq!(counter.next(), None);
        assert_eq!(counter.next(), None);
    }
}
