//! 固定目标的辅助连接与原始回落；绝对握手期限由调用方统一施加。
//!
//! 此处只解释有界 record 布局，不能解密或认证目标的加密握手消息。
//! Target 始终保留原 socket 和每次 read 得到的全部下行字节，包括取消时的半条 record。
use std::{
    io,
    net::{IpAddr, SocketAddr},
    ops::Range,
    time::Duration,
};

use rustls::server::reality::RecordPlan;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    time::{Instant, sleep_until, timeout},
};

use crate::{
    config::Reality,
    forward::{self, Context},
    session::{Host, Target as Destination},
};

const MAX_CAPTURE: usize = 131_072;
const MAX_RECORDS: usize = 32;
const MAX_PAYLOAD: usize = 18_432;
const MAX_SERVER_HELLO: usize = 2048;
const READ_CHUNK: usize = 4096;
const COPY_BUFFER: usize = 16 * 1024;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "REALITY 目标模板无效或超限")
}

fn elapsed() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "REALITY 固定目标期限已到")
}

// 不派生 Debug：保存的原始报文不属于可公开的错误诊断。
pub(crate) struct Target {
    stream: TcpStream,
    capture: Capture,
    template_started: bool,
}

impl Target {
    /// 调用方持有 accepted/handshake 许可，并将此操作包在同一绝对握手期限内。
    /// 不调用业务路由/Counted，DNS 与逐地址拨号仍共享现有预算。
    pub(crate) async fn connect(
        config: &Reality,
        ctx: &Context,
        listeners: &[SocketAddr],
        prefix: &[u8],
    ) -> io::Result<Self> {
        if prefix.len() > MAX_CAPTURE || config.target.port == 0 {
            return Err(invalid());
        }
        let destination = Destination {
            host: match config.target.host.parse::<IpAddr>() {
                Ok(ip) => Host::Ip(ip),
                Err(_) => Host::Domain(config.target.host.clone()),
            },
            port: config.target.port,
        };
        timeout(Duration::from_millis(ctx.limits.dial_timeout_ms), async {
            let addresses = ctx.dns.resolve(&destination).await?;
            // 先检查整个解析结果，不能先拨一项后才发现其余项指向本 Server。
            for address in &addresses {
                check_address(*address, listeners)?;
            }
            let mut stream = forward::dial_addresses(
                &addresses,
                Duration::from_millis(ctx.limits.dial_attempt_timeout_ms),
            )
            .await?;
            stream.write_all(prefix).await?;
            Ok(Self {
                stream,
                capture: Capture::default(),
                template_started: false,
            })
        })
        .await
        .map_err(|_| elapsed())?
    }

    /// 每个连接只采集一次；失败或 timeout 取消后仍可将 self 移入 fallback。
    /// 原始 SH 的套件/组/SID/扩展检查由受限 rustls hook 再执行。
    pub(crate) async fn template(&mut self) -> io::Result<(Vec<u8>, RecordPlan)> {
        if self.template_started {
            return Err(invalid());
        }
        self.template_started = true;
        collect_template(&mut self.stream, &mut self.capture).await
    }

    /// 消费原连接，先回放已读下行，再排空原始双向流；没有第二次目标拨号。
    /// 两向 pump 是同一 future 的子 future，不生成后台任务；外层 drop 即关闭两 socket。
    pub(crate) async fn fallback(self, mut client: TcpStream, config: &Reality) -> io::Result<()> {
        let idle = Duration::from_millis(config.fallback_idle_timeout_ms);
        let total = Duration::from_millis(config.fallback_max_duration_ms);
        if idle.is_zero() || total < idle {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "REALITY 回落期限无效",
            ));
        }
        let now = Instant::now();
        let deadline = now.checked_add(total).ok_or_else(elapsed)?;
        let (progress, mut observed) = watch::channel(now);
        let Self {
            mut stream,
            capture,
            ..
        } = self;
        let (client_read, client_write) = client.split();
        let (target_read, target_write) = stream.split();
        let relay = async {
            tokio::try_join!(
                pump(client_read, target_write, &[], &progress),
                pump(target_read, client_write, &capture.bytes, &progress),
            )?;
            Ok(())
        };
        tokio::pin!(relay);
        loop {
            let last = *observed.borrow_and_update();
            let idle_deadline = last.checked_add(idle).ok_or_else(elapsed)?;
            tokio::select! {
                biased;
                _ = sleep_until(deadline) => return Err(elapsed()),
                _ = sleep_until(idle_deadline) => {
                    // 同一 poll 中另一方向可能刚推进，不能按旧快照误判 idle。
                    if Instant::now().duration_since(*observed.borrow()) >= idle {
                        return Err(elapsed());
                    }
                }
                result = &mut relay => return result,
                _ = observed.changed() => {}
            }
        }
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}

fn check_address(address: SocketAddr, listeners: &[SocketAddr]) -> io::Result<()> {
    let ip = canonical(address.ip());
    if address.port() == 0
        || ip.is_unspecified()
        || listeners.iter().any(|listener| {
            let listening_ip = canonical(listener.ip());
            listener.port() == address.port()
                && (listening_ip.is_unspecified()
                    || listening_ip == ip
                    || (listening_ip.is_loopback() && ip.is_loopback()))
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "REALITY 固定目标不能指向本 Server 或未指定地址",
        ));
    }
    Ok(())
}

#[derive(Default)]
struct Capture {
    bytes: Vec<u8>,
    cursor: usize,
    records: usize,
}

struct Record {
    typ: u8,
    payload: Range<usize>,
    total: usize,
}

impl Capture {
    async fn fill_to<S: AsyncRead + Unpin>(
        &mut self,
        stream: &mut S,
        end: usize,
    ) -> io::Result<()> {
        if end > MAX_CAPTURE {
            return Err(invalid());
        }
        while self.bytes.len() < end {
            let mut buffer = [0; READ_CHUNK];
            let remaining = MAX_CAPTURE - self.bytes.len();
            let n = stream
                .read(&mut buffer[..remaining.min(READ_CHUNK)])
                .await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "REALITY 目标模板截断",
                ));
            }
            // 必须在下一 await 前保存，不能先 read_exact 到局部 Vec 再追加。
            self.bytes.extend_from_slice(&buffer[..n]);
        }
        Ok(())
    }

    fn header(&self, start: usize) -> io::Result<(u8, usize)> {
        let header = self
            .bytes
            .get(start..start.checked_add(5).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        if header[1..3] != [3, 3] {
            return Err(invalid());
        }
        let n = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let end = start
            .checked_add(5)
            .and_then(|v| v.checked_add(n))
            .ok_or_else(invalid)?;
        if n > MAX_PAYLOAD || end > MAX_CAPTURE {
            return Err(invalid());
        }
        Ok((header[0], end))
    }

    async fn record<S: AsyncRead + Unpin>(&mut self, stream: &mut S) -> io::Result<Record> {
        if self.records >= MAX_RECORDS {
            return Err(invalid());
        }
        let start = self.cursor;
        self.fill_to(stream, start.checked_add(5).ok_or_else(invalid)?)
            .await?;
        let (typ, end) = self.header(start)?;
        self.fill_to(stream, end).await?;
        self.cursor = end;
        self.records += 1;
        Ok(Record {
            typ,
            payload: start + 5..end,
            total: end - start,
        })
    }

    /// 只查看本次必需读取顺带取得的字节，不 read/peek/等待可选 record。
    /// 所有尾部仍保留给 fallback；局部 TLS 不会收到目标的 opaque 密文。
    fn optional_slot(&self) -> io::Result<Option<usize>> {
        let mut start = self.cursor;
        let mut records = self.records;
        let mut slot = None;
        while self.bytes.len() - start >= 5 {
            if records >= MAX_RECORDS {
                return Err(invalid());
            }
            let (typ, end) = self.header(start)?;
            records += 1;
            if end > self.bytes.len() {
                break;
            }
            if start == self.cursor && typ == 23 {
                slot = Some(end - start);
            }
            start = end;
        }
        if start < self.bytes.len() && records >= MAX_RECORDS {
            return Err(invalid());
        }
        Ok(slot)
    }
}

async fn collect_template<S: AsyncRead + Unpin>(
    stream: &mut S,
    capture: &mut Capture,
) -> io::Result<(Vec<u8>, RecordPlan)> {
    let mut raw_sh = Vec::new();
    let mut sh_records = 0;
    let sh_total = loop {
        let record = capture.record(stream).await?;
        if record.typ != 22
            || raw_sh
                .len()
                .checked_add(record.payload.len())
                .is_none_or(|n| n > MAX_SERVER_HELLO)
        {
            return Err(invalid());
        }
        raw_sh.extend_from_slice(&capture.bytes[record.payload]);
        sh_records += 1;
        if raw_sh.len() < 4 {
            continue;
        }
        if raw_sh[0] != 2 {
            return Err(invalid());
        }
        let n = ((usize::from(raw_sh[1]) << 16)
            | (usize::from(raw_sh[2]) << 8)
            | usize::from(raw_sh[3]))
        .checked_add(4)
        .ok_or_else(invalid)?;
        if n > MAX_SERVER_HELLO || raw_sh.len() > n {
            return Err(invalid());
        }
        if raw_sh.len() == n {
            // 可以收齐跨 record SH，当前本地输出计划不能表达它；保留原文回落。
            if sh_records != 1 {
                return Err(invalid());
            }
            break record.total;
        }
    };
    let next = capture.record(stream).await?;
    let (ccs_total, first) = if next.typ == 20 {
        if capture.bytes[next.payload] != [1] {
            return Err(invalid());
        }
        (next.total, capture.record(stream).await?)
    } else {
        (0, next)
    };
    if first.typ != 23 {
        return Err(invalid());
    }
    let mut encrypted = vec![first.total];
    if first.total <= 512 {
        for _ in 0..3 {
            let record = capture.record(stream).await?;
            if record.typ != 23 {
                return Err(invalid());
            }
            encrypted.push(record.total);
        }
    }
    let optional = capture.optional_slot()?;
    // 进一步应用 TLS1.3 可发送长度（比通用预读18432更严格）及七槽/flight上限。
    let plan = RecordPlan::new(sh_total, ccs_total, encrypted, optional).map_err(|_| invalid())?;
    Ok((raw_sh, plan))
}

async fn write_progress<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut bytes: &[u8],
    progress: &watch::Sender<Instant>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let n = writer.write(bytes).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "REALITY 回落写入无进展",
            ));
        }
        bytes = &bytes[n..];
        progress.send_replace(Instant::now());
    }
    Ok(())
}

async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    initial: &[u8],
    progress: &watch::Sender<Instant>,
) -> io::Result<()> {
    write_progress(&mut writer, initial, progress).await?;
    let mut buffer = [0; COPY_BUFFER];
    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        progress.send_replace(Instant::now());
        write_progress(&mut writer, &buffer[..n], progress).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use tokio::{
        io::duplex,
        net::{TcpListener, UdpSocket},
        time::sleep,
    };

    fn configuration(port: u16) -> Reality {
        serde_json::from_value(serde_json::json!({
            "target":{"host":"127.0.0.1","port":port},
            "private_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "server_names":["local.test"],"short_ids":[""]
        }))
        .unwrap()
    }

    fn context() -> Context {
        let config = Config::from_json(
            &serde_json::json!({
                "version":1,
                "inbounds":[{"type":"socks5","tag":"s","listen":"127.0.0.1:0"}],
                "outbounds":[{"type":"reject","tag":"reject"}],
                "route":{"default":"reject"}
            })
            .to_string(),
        )
        .unwrap();
        Context::new(&config).unwrap()
    }

    fn record(typ: u8, payload: &[u8]) -> Vec<u8> {
        let mut wire = vec![typ, 3, 3];
        wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(payload);
        wire
    }

    fn hello() -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.push(32);
        body.extend_from_slice(&[9; 32]);
        body.extend_from_slice(&[0x13, 1, 0]);
        let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 51, 0, 36, 0, 29, 0, 32];
        extensions.extend_from_slice(&[5; 32]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut raw = vec![2, 0, (body.len() >> 8) as u8, body.len() as u8];
        raw.extend_from_slice(&body);
        raw
    }

    async fn sockets() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn target_aggregate_without_ccs_and_buffered_empty_slot() {
        let raw = hello();
        let wire = [
            record(22, &raw),
            record(23, &[1; 600]),
            record(23, &[2; 40]),
        ]
        .concat();
        let (mut sender, mut reader) = duplex(4096);
        sender.write_all(&wire).await.unwrap();
        let mut capture = Capture::default();
        let (collected, plan) = timeout(
            Duration::from_millis(200),
            collect_template(&mut reader, &mut capture),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(collected, raw);
        assert_eq!(capture.bytes, wire);
        let description = format!("{plan:?}");
        assert!(description.contains("ccs_total: 0"));
        assert!(description.contains("encrypted: [605]"));
        assert!(description.contains("empty_app: Some(45)"));
    }

    #[tokio::test]
    async fn target_separate_records_and_partial_optional_never_wait() {
        let raw = hello();
        let mut wire = record(22, &raw);
        wire.extend_from_slice(&record(20, &[1]));
        for length in [40, 200, 70, 60] {
            wire.extend_from_slice(&record(23, &vec![3; length]));
        }
        wire.extend_from_slice(&[23, 3, 3, 0, 100, 4, 4]);
        let (mut sender, mut reader) = duplex(4096);
        sender.write_all(&wire).await.unwrap();
        let mut capture = Capture::default();
        let (_, plan) = timeout(
            Duration::from_millis(200),
            collect_template(&mut reader, &mut capture),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(capture.bytes, wire);
        let description = format!("{plan:?}");
        assert!(description.contains("ccs_total: 6"));
        assert!(description.contains("encrypted: [45, 205, 75, 65]"));
        assert!(description.contains("empty_app: None"));
    }

    #[tokio::test]
    async fn target_fragmented_sh_and_incompatible_records_retain_original_wire() {
        let raw = hello();
        let cases = [
            [record(22, &raw[..2]), record(22, &raw[2..])].concat(),
            [record(22, &raw), record(20, &[0])].concat(),
            [record(22, &raw), record(20, &[1, 1])].concat(),
            [record(22, &raw), record(21, &[2, 40])].concat(),
            [record(22, &raw), record(23, &[0; 16_402])].concat(),
        ];
        for wire in cases {
            let (mut sender, mut reader) = duplex(32_768);
            sender.write_all(&wire).await.unwrap();
            sender.shutdown().await.unwrap();
            let mut capture = Capture::default();
            assert!(collect_template(&mut reader, &mut capture).await.is_err());
            assert_eq!(capture.bytes, wire[..capture.bytes.len()]);
            assert!(capture.bytes.len() <= MAX_CAPTURE);
        }
    }

    #[tokio::test]
    async fn target_capture_record_payload_count_and_total_limits() {
        let too_big = [22, 3, 3, 0x48, 1]; // 18433, before allocating its payload.
        let many = record(22, &[]).repeat(MAX_RECORDS + 1);
        for wire in [too_big.to_vec(), many] {
            let (mut sender, mut reader) = duplex(4096);
            sender.write_all(&wire).await.unwrap();
            let mut capture = Capture::default();
            assert!(collect_template(&mut reader, &mut capture).await.is_err());
            assert!(capture.bytes.len() <= MAX_CAPTURE);
            assert!(capture.records <= MAX_RECORDS);
        }
        let wire = record(23, &vec![0; MAX_PAYLOAD]).repeat(8);
        let (mut sender, mut reader) = duplex(MAX_CAPTURE * 2);
        sender.write_all(&wire).await.unwrap();
        let mut capture = Capture::default();
        for _ in 0..7 {
            capture.record(&mut reader).await.unwrap();
        }
        assert_eq!(
            capture.record(&mut reader).await.err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(capture.bytes.len() <= MAX_CAPTURE);
    }

    #[test]
    fn target_self_loop_guards_include_all_listeners_and_ip_aliases() {
        let listeners: Vec<SocketAddr> = ["192.0.2.1:443", "127.0.0.1:8443", "[::]:9443"]
            .iter()
            .map(|v| v.parse().unwrap())
            .collect();
        for address in [
            "192.0.2.1:443",
            "127.0.0.2:8443",
            "[::1]:8443",
            "[::ffff:127.0.0.2]:8443",
            "198.51.100.2:9443",
            "0.0.0.0:9999",
            "[::]:9999",
            "[::ffff:0.0.0.0]:9999",
        ] {
            assert!(check_address(address.parse().unwrap(), &listeners).is_err());
        }
        assert!(check_address("127.0.0.2:8444".parse().unwrap(), &listeners).is_ok());
        assert!(check_address("192.0.2.2:443".parse().unwrap(), &listeners).is_ok());
    }

    #[tokio::test]
    async fn target_connect_rejects_listener_before_sending_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = configuration(addr.port());
        assert_eq!(
            Target::connect(&config, &context(), &[addr], b"prefix")
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(
            timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn target_cancelled_partial_records_replay_once_and_half_close() {
        for partial in [vec![22, 3, 3], vec![22, 3, 3, 0, 20, 2, 0]] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let config = configuration(listener.local_addr().unwrap().port());
            // 默认业务路由为Reject；辅助固定目标不经过业务路由。
            let mut target = Target::connect(&config, &context(), &[], b"prefix")
                .await
                .unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut prefix = [0; 6];
            peer.read_exact(&mut prefix).await.unwrap();
            assert_eq!(&prefix, b"prefix");
            peer.write_all(&partial).await.unwrap();
            assert!(
                timeout(Duration::from_millis(20), target.template())
                    .await
                    .is_err()
            );
            assert_eq!(target.capture.bytes, partial);
            peer.write_all(b"rest").await.unwrap();
            let (mut user, client) = sockets().await;
            let peer_side = async {
                let mut uplink = Vec::new();
                peer.read_to_end(&mut uplink).await.unwrap();
                assert_eq!(uplink, b"body");
                peer.write_all(b"tail").await.unwrap();
                peer.shutdown().await.unwrap();
            };
            let user_side = async {
                user.write_all(b"body").await.unwrap();
                user.shutdown().await.unwrap();
                let mut downlink = Vec::new();
                user.read_to_end(&mut downlink).await.unwrap();
                assert_eq!(downlink, [partial.as_slice(), b"resttail"].concat());
            };
            timeout(Duration::from_secs(2), async {
                let (result, (), ()) =
                    tokio::join!(target.fallback(client, &config), peer_side, user_side);
                result.unwrap();
            })
            .await
            .unwrap();
            assert!(
                timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn target_template_error_and_direct_fallback_preserve_only_original_connection() {
        for collect in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let config = configuration(listener.local_addr().unwrap().port());
            let mut target = Target::connect(&config, &context(), &[], b"once")
                .await
                .unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut prefix = [0; 4];
            peer.read_exact(&mut prefix).await.unwrap();
            assert_eq!(&prefix, b"once");
            let response = record(21, &[2, 40]);
            peer.write_all(&response).await.unwrap();
            peer.shutdown().await.unwrap();
            if collect {
                assert!(target.template().await.is_err());
                assert_eq!(target.capture.bytes, response);
            }
            let (mut user, client) = sockets().await;
            user.shutdown().await.unwrap();
            let user_side = async {
                let mut bytes = Vec::new();
                user.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, response);
            };
            let (result, ()) = tokio::join!(target.fallback(client, &config), user_side);
            result.unwrap();
        }
    }

    #[tokio::test]
    async fn target_fallback_idle_and_total_deadlines_are_distinct() {
        let (stream, mut peer) = sockets().await;
        let (mut user, client) = sockets().await;
        let mut config = configuration(1);
        config.fallback_idle_timeout_ms = 25;
        config.fallback_max_duration_ms = 100;
        let target = Target {
            stream,
            capture: Capture::default(),
            template_started: false,
        };
        assert_eq!(
            target.fallback(client, &config).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        let mut byte = [0];
        assert_eq!(user.read(&mut byte).await.unwrap(), 0);
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);

        let (stream, mut peer) = sockets().await;
        let (mut user, client) = sockets().await;
        let target = Target {
            stream,
            capture: Capture::default(),
            template_started: false,
        };
        let user_side = async {
            let mut data = [0];
            loop {
                if user.write_all(&[1]).await.is_err() || user.read_exact(&mut data).await.is_err()
                {
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
        };
        let peer_side = async {
            let mut data = [0];
            while peer.read_exact(&mut data).await.is_ok() {
                if peer.write_all(&data).await.is_err() {
                    break;
                }
            }
        };
        let began = Instant::now();
        timeout(Duration::from_secs(2), async {
            let (result, (), ()) =
                tokio::join!(target.fallback(client, &config), user_side, peer_side);
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        })
        .await
        .unwrap();
        assert!(began.elapsed() >= Duration::from_millis(90));
    }

    #[tokio::test]
    async fn target_dns_uses_shared_permit_and_total_dial_budget() {
        use hickory_resolver::config::{LookupIpStrategy, ResolveHosts, ResolverOpts};
        let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut options = ResolverOpts::default();
        options.ip_strategy = LookupIpStrategy::Ipv4Only;
        options.use_hosts_file = ResolveHosts::Never;
        options.attempts = 1;
        let mut ctx = context();
        ctx.limits.dial_timeout_ms = 30;
        ctx.dns = crate::dns::Dns::new(
            crate::dns::udp_resolver(dns.local_addr().unwrap(), options).unwrap(),
            1,
            Duration::from_secs(1),
        );
        let mut config = configuration(443);
        config.target.host = "controlled.test.".into();
        let mut pending = Box::pin(Target::connect(&config, &ctx, &[], b"prefix"));
        let mut query = [0; 2048];
        tokio::select! {
            result = &mut pending => panic!("目标请求过早结束: {:?}", result.err().map(|e| e.kind())),
            received = dns.recv_from(&mut query) => { received.unwrap(); }
        }
        let destination = Destination {
            host: Host::Domain("budget.test.".into()),
            port: 443,
        };
        assert_eq!(
            ctx.dns.resolve(&destination).await.unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(pending.await.err().unwrap().kind(), io::ErrorKind::TimedOut);
        // 超时丢弃lookup后共享DNS许可已归还；第二个lookup不再立即WouldBlock。
        assert!(
            timeout(Duration::from_millis(5), ctx.dns.resolve(&destination))
                .await
                .is_err()
        );
    }
}
