// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Egress service supervision and bounded graceful shutdown.

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use crate::common::ShutdownSignals;
use crate::telemetry::{InstanceRole, TelemetryServer};

use super::Egress;

impl Egress {
    pub async fn run(self) -> Result<()> {
        self.run_inner(None).await
    }

    /// 以外部停止令牌运行；供嵌入其他运行时使用（不等待进程信号）。
    pub async fn run_with_stop(self, stop: CancellationToken) -> Result<()> {
        self.run_inner(Some(stop)).await
    }

    async fn run_inner(self, external_stop: Option<CancellationToken>) -> Result<()> {
        let mut signals = ShutdownSignals::new()?;
        self.forward
            .logger
            .info(format_args!("egress starting: {}", self.effective));
        let stop = external_stop.clone().unwrap_or_else(CancellationToken::new);
        let observation = match TelemetryServer::bind(
            InstanceRole::Egress,
            self.config.endpoint(),
            self.forward.stats.clone(),
        ) {
            Ok(server) => Some(tokio::spawn(server.run(stop.clone()))),
            Err(error) => {
                self.forward
                    .logger
                    .error(format_args!("local ipc unavailable: {error:#}"));
                None
            }
        };
        let mut maintenance: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> =
            if self.config.net == crate::vector::config::CarrierMode::Tcp {
                Box::pin(self.maintain_tls())
            } else {
                Box::pin(self.maintain_connection())
            };
        let mut maintenance_finished = false;
        let failure = tokio::select! {
            _ = stop.cancelled(), if external_stop.is_some() => None,
            signal = signals.recv(), if external_stop.is_none() => signal.map(|_| ()).err(),
            _ = &mut maintenance => {
                maintenance_finished = true;
                Some(anyhow::anyhow!("Egress maintenance exited unexpectedly"))
            },
        };
        self.forward.shutdown.cancel();
        let drained = maintenance_finished
            || tokio::time::timeout(self.forward.runtime.shutdown_timeout, &mut maintenance)
                .await
                .is_ok();
        drop(maintenance);
        stop.cancel();
        if let Some(observation) = observation {
            let _ = observation.await;
        }
        self.forward
            .logger
            .info(format_args!("egress shutdown complete"));
        if let Some(error) = failure {
            return Err(error);
        }
        anyhow::ensure!(drained, "Egress shutdown timed out");
        Ok(())
    }
}
