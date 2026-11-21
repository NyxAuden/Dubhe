//! REALITY：先认证及防重放，再取固定目标模板；本地输出提交后不可回落。
use std::{
    io::{self, Cursor},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use rustls::{ServerConfig, ServerConnection, sign::SingleCertAndKey};
use sha2::{Digest, Sha256};
use tokio::{
    net::TcpStream,
    time::{Instant, timeout_at},
};

use super::controlled::Controlled;
use crate::{
    config::{PreparedReality, Reality},
    forward::Context,
};

pub(crate) mod auth;
mod certificate;
pub(crate) mod hello;
pub(crate) mod replay;
mod target;

pub(crate) type Stream = Controlled<hello::PrefixIo<TcpStream>>;

pub(crate) struct Prepared {
    config: Reality,
    imported: PreparedReality,
    identity: Arc<certificate::Identity>,
    replay: Arc<replay::ReplayPool>,
    ttl: Duration,
    listeners: Arc<[SocketAddr]>,
    alpn: Vec<Vec<u8>>,
}

pub(crate) enum Accepted {
    Local(Box<Stream>),
    Fallback {
        client: TcpStream,
        target: target::Target,
    },
}

pub(crate) fn check(config: &Reality) -> io::Result<()> {
    let imported = config.prepare().map_err(|_| tls_error(()))?;
    let identity = Arc::new(certificate::Identity::new(imported.mldsa65_seed.as_ref())?);
    identity.resolver([0; 32], Vec::new()).initial()?;
    Ok(())
}

impl Prepared {
    pub(crate) fn new(
        config: Reality,
        imported: PreparedReality,
        replay: Arc<replay::ReplayPool>,
        ttl: Duration,
        listeners: Arc<[SocketAddr]>,
        alpn: Vec<Vec<u8>>,
    ) -> io::Result<Self> {
        let identity = Arc::new(certificate::Identity::new(imported.mldsa65_seed.as_ref())?);
        Ok(Self {
            config,
            imported,
            identity,
            replay,
            ttl,
            listeners,
            alpn,
        })
    }

    pub(crate) async fn fallback(
        &self,
        client: TcpStream,
        target: target::Target,
    ) -> io::Result<()> {
        target.fallback(client, &self.config).await
    }

    pub(crate) async fn accept(
        &self,
        mut client: TcpStream,
        ctx: &Context,
        deadline: Instant,
    ) -> io::Result<Accepted> {
        let hello = timeout_at(deadline, hello::read(&mut client))
            .await
            .map_err(|_| timed_out())??;
        let authentication =
            auth::authenticate(&self.config, &self.imported, &hello, self.replay.now()?)?;
        if let Some(authentication) = &authentication {
            self.replay.insert(
                authentication.server_public,
                Sha256::digest(&hello.raw_ch).into(),
                self.ttl,
            )?;
        }
        let mut target = timeout_at(
            deadline,
            target::Target::connect(&self.config, ctx, &self.listeners, &hello.wire_prefix),
        )
        .await
        .map_err(|_| timed_out())??;
        let Some(authentication) = authentication else {
            return Ok(Accepted::Fallback { client, target });
        };
        let template = timeout_at(deadline, target.template()).await;
        let Ok(Ok((raw_sh, plan))) = template else {
            return Ok(Accepted::Fallback { client, target });
        };
        let session = match self.prepare_session(&hello, authentication.auth_key, raw_sh, plan) {
            Ok(session) => session,
            Err(_) => return Ok(Accepted::Fallback { client, target }),
        };
        if Instant::now() >= deadline {
            return Ok(Accepted::Fallback { client, target });
        }
        // 不可逆提交闩锁：从这里起即使首次 poll_write 为 Pending 也不保留回落选项。
        // 辅助目标没有子任务；析构即关闭唯一 socket，不另拨目标。
        // prefix 已完整喂入内存预检 session，不能再喂一次；余下 socket 原文仍只读一次。
        let io = hello::PrefixIo::new(Vec::new(), client);
        let stream = commit(io, session, target, deadline).await?;
        Ok(Accepted::Local(Box::new(stream)))
    }

    fn prepare_session(
        &self,
        hello: &hello::Hello,
        auth_key: [u8; 32],
        raw_sh: Vec<u8>,
        plan: rustls::server::reality::RecordPlan,
    ) -> io::Result<ServerConnection> {
        let resolver = Arc::new(self.identity.resolver(auth_key, hello.raw_ch.clone()));
        let initial = resolver.initial()?;
        let hook =
            rustls::server::reality::Config::new(raw_sh, plan, resolver).map_err(tls_error)?;
        if !hello
            .cipher_suites
            .contains(&u16::from(hook.cipher_suite()))
            || !hello
                .supported_groups
                .contains(&u16::from(hook.named_group()))
        {
            return Err(tls_error(()));
        }
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider
            .cipher_suites
            .retain(|suite| suite.suite() == hook.cipher_suite());
        provider.kx_groups = vec![match hook.named_group() {
            rustls::NamedGroup::X25519 => rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::NamedGroup::X25519MLKEM768 => {
                rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768
            }
            _ => return Err(tls_error(())),
        }];
        let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls_error)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(initial)));
        config.send_tls13_tickets = 0;
        config.max_tls13_tickets = 0;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.max_early_data_size = 0;
        config.send_half_rtt_data = false;
        config.enable_secret_extraction = false;
        config.cert_compressors.clear();
        config.alpn_protocols = self.alpn.clone();
        config.reality = Some(Arc::new(hook));
        let mut session = ServerConnection::new(Arc::new(config)).map_err(tls_error)?;
        session.set_buffer_limit(Some(131_072));
        let mut input = Cursor::new(&hello.wire_prefix);
        while input.position() < hello.wire_prefix.len() as u64 {
            if session.read_tls(&mut input)? == 0 {
                return Err(tls_error(()));
            }
            session.process_new_packets().map_err(tls_error)?;
        }
        if !session.wants_write() || !session.is_handshaking() {
            return Err(tls_error(()));
        }
        Ok(session)
    }
}

// 消费辅助连接的类型化提交边界：调用后无 Target 可用于回落，即使首写 Pending。
async fn commit<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    io: S,
    session: ServerConnection,
    target: impl Sized,
    deadline: Instant,
) -> io::Result<Controlled<S>> {
    drop(target);
    timeout_at(deadline, Controlled::accept_prepared(io, session))
        .await
        .map_err(|_| timed_out())?
}

#[cfg(test)]
mod controlled_tests;
#[cfg(test)]
mod tests;

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "REALITY 握手超时")
}
fn tls_error(_: impl Sized) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "REALITY TLS 预检失败")
}
