//! 配置应用状态：让面板能确认「内核接受了哪一版配置、是否真的在跑」。
//!
//! 只有 CLI 的重载协调器（`main.rs` 的 SIGHUP 分支）是写入方。`Server` 与
//! `admin` 只读取快照，避免多处各自推算版本。
//!
//! 设计要点：
//!
//! - `active_revision` 只在**确认生效**时加一：热替换成功、重建后新监听就绪、
//!   只看标签的元数据变更。校验拒绝、回退、单纯证书轮换都不加。
//! - `last_apply` 描述**最近一次尝试**。`rolled_back` 表示新配置没跑起来、
//!   旧配置已恢复服务；它不是成功。
//! - `pending` 期间 `active_*` 指上一版确认值，不代表旧监听此刻一定在线。
//! - 过期 attempt 不得覆盖新 attempt。

use std::sync::{Arc, Mutex};

use serde::Serialize;

/// 状态契约版本；与配置文件的 `version` 无关。
pub const API_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyMode {
    /// 收到重载但候选配置未能读取或未通过校验。
    Validate,
    /// 仅证书轮换。
    Tls,
    /// 只有部署标签变化，业务配置未变。
    Metadata,
    /// 零停机热替换。
    Hot,
    /// 停止旧实例后重新绑定。
    Rebind,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyResult {
    /// 正在处理。
    Pending,
    /// 已确认生效。
    Applied,
    /// 配置被拒绝，旧实例继续运行。
    Rejected,
    /// 新配置未生效，旧配置已恢复服务。
    RolledBack,
    /// 无需动作（例如没有可轮换的 TLS 入口）。
    Noop,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyErrorCode {
    ConfigUnreadable,
    ConfigInvalid,
    DeploymentIdReused,
    HotApplyFailed,
    TlsReloadFailed,
    CandidateBindFailed,
}

/// 一次尝试的终态；对外只暴露稳定枚举，不含错误原文与配置内容。
#[derive(Clone, Debug, Serialize)]
pub struct ApplyRecord {
    pub attempt: u64,
    pub requested_deployment_id: Option<String>,
    pub mode: ApplyMode,
    pub result: ApplyResult,
    pub error_code: Option<ApplyErrorCode>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StatusSnapshot {
    pub api_version: u32,
    pub instance_id: String,
    pub active_revision: u64,
    pub active_deployment_id: Option<String>,
    pub last_apply: Option<ApplyRecord>,
}

#[derive(Default)]
struct Inner {
    revision: u64,
    deployment_id: Option<String>,
    attempt: u64,
    record: Option<ApplyRecord>,
    /// 重建类结果要等到新监听 `ready` 才提交，避免把「拿到 socket」
    /// 报成「已启动」。由 `Server::run_with_tasks` 的 ready 点消费。
    staged: Option<Staged>,
}

/// 等就绪再提交的终态。
struct Staged {
    attempt: u64,
    mode: ApplyMode,
    result: ApplyResult,
    error_code: Option<ApplyErrorCode>,
    deployment_id: Option<String>,
}

/// 进程内共享的应用状态。`instance_id` 在构造时固定。
pub struct ApplyState {
    instance_id: String,
    inner: Mutex<Inner>,
}

/// 一次尝试的句柄；`finish` 之外的方法都只改本次 attempt。
#[derive(Clone, Copy)]
pub struct AttemptId(u64);

impl ApplyState {
    /// 由 CLI 在启动成功后创建；`instance_id` 用系统随机源生成。
    pub fn new(active_deployment_id: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            instance_id: random_id(),
            inner: Mutex::new(Inner {
                // 首次启动即视为第 1 代已生效。
                revision: 1,
                deployment_id: active_deployment_id,
                attempt: 0,
                record: None,
                staged: None,
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// 开始一次尝试：attempt 加一，先发布 `pending`。
    ///
    /// `requested_deployment_id` 只在候选配置**成功反序列化并通过静态校验**
    /// 后才有值；由调用方在此之前传 `None`。
    pub fn begin(&self) -> AttemptId {
        let mut inner = self.lock();
        inner.attempt += 1;
        let attempt = inner.attempt;
        inner.record = Some(ApplyRecord {
            attempt,
            requested_deployment_id: None,
            mode: ApplyMode::Validate,
            result: ApplyResult::Pending,
            error_code: None,
        });
        AttemptId(attempt)
    }

    /// 记录本次尝试的候选部署标签（已通过解析与静态校验）。
    pub fn set_candidate(&self, attempt: AttemptId, deployment_id: Option<String>) {
        let mut inner = self.lock();
        if let Some(record) = inner.record.as_mut()
            && record.attempt == attempt.0
        {
            record.requested_deployment_id = deployment_id;
        }
    }

    /// 切换到某个阶段的 `pending`（例如确定要走重绑）。
    pub fn set_mode(&self, attempt: AttemptId, mode: ApplyMode) {
        let mut inner = self.lock();
        if let Some(record) = inner.record.as_mut()
            && record.attempt == attempt.0
        {
            record.mode = mode;
            record.result = ApplyResult::Pending;
        }
    }

    /// 结束本次尝试。只有 `Applied` 且带标签时才推进 `active_*`。
    pub fn finish(
        &self,
        attempt: AttemptId,
        mode: ApplyMode,
        result: ApplyResult,
        error_code: Option<ApplyErrorCode>,
        applied_deployment_id: Option<String>,
    ) {
        let mut inner = self.lock();
        // 过期 attempt 不得覆盖更新的记录。
        if inner.attempt != attempt.0 {
            return;
        }
        inner.record = Some(ApplyRecord {
            attempt: attempt.0,
            requested_deployment_id: inner
                .record
                .as_ref()
                .and_then(|record| record.requested_deployment_id.clone()),
            mode,
            result: result.clone(),
            error_code,
        });
        if matches!(result, ApplyResult::Applied) {
            inner.revision += 1;
            inner.deployment_id = applied_deployment_id;
        }
    }

    /// 登记一个「等就绪再提交」的终态。重建成功、回退成功都走这里。
    pub fn stage_commit(
        &self,
        attempt: AttemptId,
        mode: ApplyMode,
        result: ApplyResult,
        error_code: Option<ApplyErrorCode>,
        applied_deployment_id: Option<String>,
    ) {
        let mut inner = self.lock();
        if inner.attempt != attempt.0 {
            return;
        }
        inner.staged = Some(Staged {
            attempt: attempt.0,
            mode,
            result,
            error_code,
            deployment_id: applied_deployment_id,
        });
    }

    /// 新实例就绪：提交暂存终态。没有暂存时什么也不做（首次启动）。
    pub fn commit_pending(&self) {
        let staged = {
            let mut inner = self.lock();
            inner.staged.take()
        };
        if let Some(staged) = staged {
            self.finish(
                AttemptId(staged.attempt),
                staged.mode,
                staged.result,
                staged.error_code,
                staged.deployment_id,
            );
        }
    }

    pub fn snapshot(&self) -> StatusSnapshot {
        let inner = self.lock();
        StatusSnapshot {
            api_version: API_VERSION,
            instance_id: self.instance_id.clone(),
            active_revision: inner.revision,
            active_deployment_id: inner.deployment_id.clone(),
            last_apply: inner.record.clone(),
        }
    }
}

impl StatusSnapshot {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self)
            .unwrap_or_else(|_| br#"{"error_code":"serialize_failed"}"#.to_vec())
    }
}

/// 32 位小写十六进制随机标识；用于 `instance_id` 与 `deployment_id`。
///
/// 是关联标记，不是认证凭据，也不是配置完整性证明。
pub fn random_id() -> String {
    let mut bytes = [0u8; 16];
    aws_lc_rs::rand::fill(&mut bytes).expect("系统随机源不可用");
    let mut out = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// 生成并校验部署标识：正好 32 位小写十六进制。
pub fn valid_deployment_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applied_advances_revision_but_rejected_does_not() {
        let state = ApplyState::new(None);
        let baseline = state.snapshot();
        assert_eq!(baseline.active_revision, 1);
        assert!(baseline.last_apply.is_none());

        let attempt = state.begin();
        state.set_candidate(attempt, Some(random_id()));
        state.finish(
            attempt,
            ApplyMode::Hot,
            ApplyResult::Applied,
            None,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
        );
        let applied = state.snapshot();
        assert_eq!(applied.active_revision, 2);
        assert_eq!(
            applied.active_deployment_id.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );

        let attempt = state.begin();
        state.finish(
            attempt,
            ApplyMode::Validate,
            ApplyResult::Rejected,
            Some(ApplyErrorCode::ConfigInvalid),
            None,
        );
        let rejected = state.snapshot();
        assert_eq!(rejected.active_revision, 2);
        assert_eq!(rejected.last_apply.as_ref().unwrap().attempt, 2);
    }

    #[test]
    fn stale_attempt_cannot_overwrite_newer_record() {
        let state = ApplyState::new(None);
        let older = state.begin();
        let newer = state.begin();
        state.finish(
            older,
            ApplyMode::Validate,
            ApplyResult::Rejected,
            Some(ApplyErrorCode::ConfigUnreadable),
            None,
        );
        let snapshot = state.snapshot();
        assert_eq!(
            snapshot.last_apply.as_ref().unwrap().attempt,
            2,
            "过期 attempt 不得覆盖新记录"
        );
        assert_eq!(snapshot.active_revision, 1);
        let _ = newer;
    }

    #[test]
    fn deployment_id_format_is_strict() {
        assert!(valid_deployment_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_deployment_id("0123456789ABCDEF0123456789abcdef"));
        assert!(!valid_deployment_id("0123456789abcdef"));
        assert!(!valid_deployment_id("0123456789abcdef0123456789abcde"));
        assert!(!valid_deployment_id("0123456789abcdef0123456789abcdeg"));
    }

    #[test]
    fn random_id_is_32_lowercase_hex_and_not_constant() {
        let first = random_id();
        let second = random_id();
        assert!(valid_deployment_id(&first));
        assert!(valid_deployment_id(&second));
        assert_ne!(first, second);
    }
}
