// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Native Rust client exposed by the `vector://` command URL.

pub(crate) mod client;
pub(crate) mod config;
mod flow;
mod socks;
pub(crate) mod tls;
pub(crate) mod udp_flow;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{Logger, ShutdownSignals, rate_limit_bytes_per_second, shutdown_timeout};
use crate::protocol::Credentials;
use crate::telemetry::{InstanceRole, TelemetryServer};
use crate::transport::{Buffers, RateLimiter, Stats};

use self::config::VectorConfig;

pub(crate) use self::client::PortalClient;
pub(crate) use self::config::PortalClientConfig;
pub(crate) use self::flow::{BoxReader, BoxWriter, OpenFlowError, TcpTunnel, TcpTunnelGuard};
pub(crate) use self::tls::fetch_certificate_fingerprint;
pub(crate) use self::udp_flow::{ReceivedUdpPacket, UdpTunnel, UdpTunnelReceiver, UdpTunnelSender};

const SOCKS_CLIENT_RESOURCE_LIMIT: usize = 1024;
const SOCKS_UDP_TARGET_RESOURCE_LIMIT: usize = 1024;

pub struct Vector {
    runtime: VectorRuntime,
}

struct VectorRuntime {
    inner: Arc<VectorInner>,
}

impl Vector {
    pub fn new(parsed_url: Url, logger: Logger) -> Result<Self> {
        VectorRuntime::new(parsed_url, logger).map(|runtime| Self { runtime })
    }

    pub async fn run(self) -> Result<()> {
        self.runtime.run().await
    }
}

pub(super) struct VectorInner {
    config: VectorConfig,
    logger: Logger,
    stats: Arc<Stats>,
    buffers: Buffers,
    rate_limiter: Option<Arc<RateLimiter>>,
    client: Arc<PortalClient>,
    local_udp_budget: Arc<Semaphore>,
    socks_client_admission: Arc<Semaphore>,
    socks_udp_target_admission: Arc<Semaphore>,
    shutdown: CancellationToken,
}

impl VectorRuntime {
    fn new(parsed_url: Url, logger: Logger) -> Result<Self> {
        let result = Self::build(parsed_url, logger);
        if result.is_err() {
            logger.flush();
        }
        result
    }

    fn build(parsed_url: Url, logger: Logger) -> Result<Self> {
        crate::common::validate_timeout_env()?;
        let udp_queue_bytes =
            crate::common::read_quic_udp_queue_bytes(&mut crate::common::env_value)?;
        let tcp_data_buf_size =
            crate::common::read_tcp_data_buf_size(&mut crate::common::env_value)?;
        let config = VectorConfig::from_url(&parsed_url)?;
        let credentials = Credentials::new(&parsed_url)?;
        let stats = Arc::new(Stats::default());
        let shutdown = CancellationToken::new();
        let read_bps = rate_limit_bytes_per_second(config.rate_mbps) as i64;
        let write_bps = rate_limit_bytes_per_second(config.etar_mbps) as i64;
        let rate_limiter = RateLimiter::new(read_bps, write_bps).map(Arc::new);
        let client = PortalClient::new(
            config.portal_client_config(),
            &credentials,
            udp_queue_bytes,
            stats.clone(),
            true,
            shutdown.clone(),
        )?;
        Ok(Self {
            inner: Arc::new(VectorInner {
                config,
                logger,
                stats,
                buffers: Buffers::new(tcp_data_buf_size),
                rate_limiter,
                client,
                local_udp_budget: Arc::new(Semaphore::new(udp_queue_bytes)),
                socks_client_admission: Arc::new(Semaphore::new(SOCKS_CLIENT_RESOURCE_LIMIT)),
                socks_udp_target_admission: Arc::new(Semaphore::new(
                    SOCKS_UDP_TARGET_RESOURCE_LIMIT,
                )),
                shutdown,
            }),
        })
    }

    pub async fn run(self) -> Result<()> {
        let mut signals = match ShutdownSignals::new()
            .context("vector::Vector::run: failed to install shutdown signal handlers")
        {
            Ok(signals) => signals,
            Err(error) => return self.start_failed(error),
        };
        let listeners =
            match socks::listen(&self.inner.config.socks.host, self.inner.config.socks.port)
                .context("vector::Vector::run: failed to open SOCKS listener")
            {
                Ok(listeners) => listeners,
                Err(error) => return self.start_failed(error),
            };
        let telemetry_shutdown = CancellationToken::new();
        let mut telemetry_tasks: JoinSet<()> = JoinSet::new();
        match TelemetryServer::bind(
            InstanceRole::Vector,
            self.inner.config.socks.endpoint(),
            self.inner.stats.clone(),
        ) {
            Ok(server) => {
                telemetry_tasks.spawn(server.run(telemetry_shutdown.clone()));
            }
            Err(error) => self
                .inner
                .logger
                .error(format_args!("local ipc unavailable: {error:#}")),
        }
        self.inner.logger.info(format_args!(
            "vector starting: {}",
            self.inner.config.effective_url()
        ));

        let mut listener_tasks = JoinSet::new();
        for listener in listeners {
            listener_tasks.spawn(socks::serve_listener(
                self.inner.clone(),
                listener,
                self.inner.shutdown.clone(),
            ));
        }

        let failure = tokio::select! {
            signal = signals.recv() => signal.err(),
            result = listener_tasks.join_next(), if !listener_tasks.is_empty() => Some(vector_listener_exit_error(result)),
        };
        self.inner.shutdown.cancel();
        let deadline = Instant::now() + shutdown_timeout();

        let cleanup = async {
            while listener_tasks.join_next().await.is_some() {}
            self.inner.client.close(deadline).await;
        };
        let (drained, forced) = tokio::select! {
            biased;
            signal = signals.recv() => {
                if let Err(error) = signal {
                    self.inner.logger.error(format_args!(
                        "shutdown signal failed: {error:#}"
                    ));
                }
                (false, true)
            }
            result = timeout_at(deadline, cleanup) => match result {
                Ok(()) => (true, false),
                Err(_) => (false, false),
            }
        };
        if !drained {
            listener_tasks.abort_all();
            while listener_tasks.join_next().await.is_some() {}
            let close_deadline = if forced { Instant::now() } else { deadline };
            self.inner.client.close(close_deadline).await;
        }
        if let Some(rate) = &self.inner.rate_limiter {
            rate.reset();
        }
        telemetry_shutdown.cancel();
        while telemetry_tasks.join_next().await.is_some() {}
        self.inner
            .logger
            .info(format_args!("vector shutdown complete"));
        self.inner.logger.flush();
        match failure {
            Some(error) => Err(error),
            None if !drained && !forced => anyhow::bail!("Vector shutdown timed out"),
            None => Ok(()),
        }
    }

    fn start_failed(&self, error: anyhow::Error) -> Result<()> {
        self.inner.logger.flush();
        Err(error)
    }
}

fn vector_listener_exit_error(
    result: Option<std::result::Result<(), tokio::task::JoinError>>,
) -> anyhow::Error {
    match result {
        Some(Ok(())) => anyhow::anyhow!("vector::Vector::run: SOCKS listener exited unexpectedly"),
        Some(Err(error)) => {
            anyhow::anyhow!("vector::Vector::run: SOCKS listener task failed: {error}")
        }
        None => {
            anyhow::anyhow!("vector::Vector::run: SOCKS listener set became empty unexpectedly")
        }
    }
}

/// 可嵌入的 Vector 出站客户端（不含 SOCKS 监听器）。
pub struct VectorClient {
    client: Arc<PortalClient>,
    shutdown: CancellationToken,
}

impl VectorClient {
    /// 与 `Vector::new` 相同的 URL 语义，但不读取 `in=` 监听参数。
    pub fn new(parsed_url: Url, _logger: Logger) -> Result<Self> {
        let (config, credentials) = PortalClientConfig::from_probe_url(&parsed_url)?;
        let shutdown = CancellationToken::new();
        let client = PortalClient::new(
            config,
            &credentials,
            crate::common::read_quic_udp_queue_bytes(&mut crate::common::env_value)?,
            Arc::new(Stats::default()),
            false,
            shutdown.clone(),
        )?;
        Ok(Self { client, shutdown })
    }

    /// 通过 Vector 打开一条 TCP 流；`host` 可为 IP 或域名。
    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<VectorStream> {
        let target = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => crate::protocol::Target::ip(std::net::SocketAddr::new(ip, port))?,
            Err(_) => crate::protocol::Target::domain(host, port)?,
        };
        let tunnel = self
            .client
            .open_tcp(&target)
            .await
            .map_err(|error| anyhow::anyhow!("Vector TCP 打开失败: {error}"))?;
        Ok(VectorStream { tunnel })
    }

    /// 使用原上游 UDP Flow 打开固定目标数据报会话，不改变 TLS/QUIC 线格式。
    pub async fn connect_udp(&self, host: &str, port: u16) -> Result<VectorDatagram> {
        let target = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => crate::protocol::Target::ip(std::net::SocketAddr::new(ip, port))?,
            Err(_) => crate::protocol::Target::domain(host, port)?,
        };
        let tunnel = udp_flow::open_udp(self.client.clone(), &target)
            .await
            .map_err(|error| anyhow::anyhow!("Vector UDP 打开失败: {error}"))?;
        Ok(VectorDatagram {
            tunnel,
            buffer: Vec::new(),
        })
    }
}

/// 可嵌入的固定目标 UDP Flow；内部生命周期和报文完全由上游 UdpTunnel 管理。
pub struct VectorDatagram {
    tunnel: UdpTunnel,
    buffer: Vec<u8>,
}

impl VectorDatagram {
    pub async fn send(&mut self, payload: &[u8]) -> Result<bool> {
        self.tunnel.send(payload).await
    }

    /// `None` 为 Flow 结束，`Some(empty)` 为真实空数据报。
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        let packet = self.tunnel.recv_into(&mut self.buffer).await?;
        Ok(packet.map(|packet| packet.payload(&self.buffer).to_vec()))
    }

    pub async fn close(&mut self) {
        self.tunnel.close().await;
    }
}

impl Drop for VectorClient {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Vector 的 TCP 隧道，实现 Tokio 字节流接口。
pub struct VectorStream {
    tunnel: TcpTunnel,
}

impl tokio::io::AsyncRead for VectorStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.tunnel).poll_read(cx, buffer)
    }
}

impl tokio::io::AsyncWrite for VectorStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.tunnel).poll_write(cx, buffer)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.tunnel).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.tunnel).poll_shutdown(cx)
    }
}
