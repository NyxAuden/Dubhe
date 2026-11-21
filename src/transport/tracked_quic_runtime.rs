//! 为专属QUIC端点拥有成熟Quinn驱动的生命周期，不修改其协议实现或定时器。
//! 关闭先正常排空，超过本地期限再取消驱动并等待future析构，不能只丢wait_idle。
use std::{future::Future, io, pin::Pin, sync::Arc};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

#[derive(Debug)]
pub(super) struct Runtime {
    children: TaskTracker,
    drivers: TaskTracker,
    force: CancellationToken,
}
impl Runtime {
    pub(super) fn new(children: TaskTracker) -> Arc<Self> {
        Arc::new(Self {
            children,
            drivers: TaskTracker::new(),
            force: CancellationToken::new(),
        })
    }
    pub(super) async fn shutdown(&self) {
        self.force.cancel();
        self.drivers.close();
        self.drivers.wait().await;
    }
}
impl quinn::Runtime for Runtime {
    fn new_timer(&self, time: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::Runtime::new_timer(&quinn::TokioRuntime, time)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        let force = self.force.clone();
        self.children.spawn(self.drivers.track_future(async move {
            tokio::select! { biased;
                _ = force.cancelled() => {},
                _ = future => {},
            }
        }));
    }
    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket)
    }
}
