//! 零停机热重载句柄。

use super::*;

pub struct HotReloadHandle {
    pub(super) shared: Arc<crate::forward::SharedContext>,
    pub(super) probe_stop: Arc<std::sync::Mutex<CancellationToken>>,
    pub(super) probe_root: CancellationToken,
    pub(super) fingerprint: Option<serde_json::Value>,
    pub(super) has_udp_listeners: bool,
}

impl HotReloadHandle {
    /// 尝试在不重建监听器的情况下替换路由/DNS/嗅探/反向配置。
    ///
    /// 返回 `Ok(true)` 表示已热替换；`Ok(false)` 表示该配置需要完整重启；
    /// 错误表示新配置无效，旧实例保持运行。
    pub fn reload(&self, config: &Config) -> Result<bool> {
        if self.has_udp_listeners {
            return Ok(false);
        }
        let Some(fingerprint) = &self.fingerprint else {
            return Ok(false);
        };
        if reload_fingerprint(config).as_ref() != Some(fingerprint) {
            return Ok(false);
        }
        let Some(previous) = self.shared.current() else {
            return Ok(false);
        };
        // 反向 portal 的隧道属于旧 Context；热替换会丢失已注册隧道。
        if previous.has_reverse()
            || previous.has_reverse_bridges()
            || !config.reverse_bridges.is_empty()
            || config
                .outbounds
                .iter()
                .any(|outbound| outbound.kind == crate::config::OutboundKind::Reverse)
        {
            return Ok(false);
        }
        let next = Arc::new(Context::reloaded(config, &previous)?);
        self.shared.replace(next.clone());
        previous.router.close_outbound_pools();
        let (old, next_token) = {
            let mut guard = crate::sync::locked(&self.probe_stop);
            let old = std::mem::replace(&mut *guard, self.probe_root.child_token());
            (old, guard.clone())
        };
        old.cancel();
        next.spawn_urltest_probes(next_token);
        Ok(true)
    }
}
