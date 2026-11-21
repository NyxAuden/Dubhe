//! 本地适配补丁：每方向固定的AEAD操作预算，不修改密码算法或nonce实现。

use std::io;

// 六个选用方法的TCP nonce至少96位；2^63次操作在回绕前保守终止。
// 不暴露生产构造参数，外部调用者不能调大此上限。
const OPERATION_LIMIT: u64 = 1 << 63;

pub(super) struct AeadBudget {
    remaining: u64,
    failed: bool,
}

impl AeadBudget {
    pub(super) fn new() -> Self {
        Self {
            remaining: OPERATION_LIMIT,
            failed: false,
        }
    }

    pub(super) fn ensure_active(&self) -> io::Result<()> {
        if self.failed {
            Err(io::Error::other("TCP AEAD direction is terminated"))
        } else {
            Ok(())
        }
    }

    // 可在poll之前检查，但只在紧邻实际密码调用时consume；Pending不扣预算。
    pub(super) fn ensure_available(&mut self) -> io::Result<()> {
        self.ensure_active()?;
        if self.remaining == 0 {
            self.failed = true;
            return Err(io::Error::other("TCP AEAD operation budget exhausted"));
        }
        Ok(())
    }

    pub(super) fn consume(&mut self) -> io::Result<()> {
        self.ensure_available()?;
        self.remaining -= 1;
        Ok(())
    }

    pub(super) fn terminate(&mut self) {
        self.failed = true;
    }

    // EIH响应只允许在writer首次加密前切换用户密钥；不能重置nonce来复活旧方向。
    #[cfg(any(test, feature = "aead-cipher-2022"))]
    pub(super) fn may_initialize_cipher(&self) -> bool {
        !self.failed && self.remaining == OPERATION_LIMIT
    }

    #[cfg(test)]
    pub(super) fn with_remaining(remaining: u64) -> Self {
        assert!(remaining <= OPERATION_LIMIT);
        Self {
            remaining,
            failed: false,
        }
    }

    #[cfg(test)]
    pub(super) fn remaining(&self) -> u64 {
        self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_budget_exact_production_boundary_and_terminal_latch() {
        let mut budget = AeadBudget::new();
        assert_eq!(budget.remaining(), 1 << 63);
        assert!(budget.may_initialize_cipher());
        budget.consume().unwrap();
        assert_eq!(budget.remaining(), (1 << 63) - 1);
        assert!(!budget.may_initialize_cipher());
        budget.remaining = 1;
        budget.consume().unwrap();
        assert_eq!(budget.remaining(), 0);
        assert!(budget.ensure_active().is_ok());
        assert!(budget.consume().is_err());
        assert!(budget.ensure_active().is_err());
        assert!(budget.consume().is_err());
        assert_eq!(budget.remaining(), 0);
    }
}
