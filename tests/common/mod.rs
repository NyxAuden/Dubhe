#![allow(dead_code)]
use dubhe::{Config, Server, telemetry::Stats};
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_util::sync::CancellationToken;

pub const PASSWORD: &str = "test-only-not-a-production-secret";

/// 等待服务端任务结束的上限。
///
/// 这不是性能断言，而是防止停机挂死时测试永久阻塞。单核机器上 QUIC
/// 关闭（发送 CONNECTION_CLOSE 并等待排空）明显慢于多核，3 秒会误报；
/// 放宽到 10 秒仍能可靠捕获真正的挂死。
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// 会话关闭只同步释放所有权，映射读任务的 abort 由运行时异步完成；
/// 断言旧端口可重新绑定时允许短暂重试，避免测试与任务回收调度竞态。
pub async fn rebind_udp(addr: SocketAddr) -> UdpSocket {
    timeout(Duration::from_secs(3), async {
        loop {
            match UdpSocket::bind(addr).await {
                Ok(socket) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                Err(error) => panic!("重新绑定 {addr} 失败: {error}"),
            }
        }
    })
    .await
    .expect("UDP 端口未在期限内释放")
}

/// 多数测试共用的基线配置。
///
/// `handshake_timeout_ms` 保持 300：多个用例依赖它来验证「非法握手在有限
/// 时间内关闭」（例如 `tests/vless.rs` 的截断首部用例只等 2 秒）。放宽它会
/// 让这些断言失败，且没有证据表明它是 CI 抖动的根因。
pub fn socks_config() -> Value {
    json!({"version":1,"inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"reject","tag":"reject"}],"route":{"default":"direct"},"limits":{"shutdown_timeout_ms":100,"handshake_timeout_ms":300,"udp_idle_timeout_ms":500}})
}
pub struct Certificate {
    pub dir: tempfile::TempDir,
    pub der: rustls::pki_types::CertificateDer<'static>,
}
/// 测试证书的有效期：相对当前时间，避免固定日期过期后测试失效。
///
/// Chromium 拒绝超过 398 天的证书有效期，这里用「昨天到 30 天后」。
pub fn test_certificate_dates() -> ((i32, u8, u8), (i32, u8, u8)) {
    fn civil_from_days(days: i64) -> (i32, u8, u8) {
        // Howard Hinnant 的 civil_from_days。
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = if m <= 2 { y + 1 } else { y };
        (year as i32, m as u8, d as u8)
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let days = now.div_euclid(86_400);
    (civil_from_days(days - 1), civil_from_days(days + 30))
}

impl Certificate {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        // Chromium（NaiveProxy 客户端）拒绝 rcgen 默认的 1975..4096 有效期，
        // 报 `cert validity too long`；用相对当前时间的 31 天。
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let (not_before, not_after) = test_certificate_dates();
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let certified = params.self_signed(&key_pair).unwrap();
        std::fs::write(dir.path().join("cert.pem"), certified.pem()).unwrap();
        let key = dir.path().join("key.pem");
        std::fs::write(&key, key_pair.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self {
            dir,
            der: certified.der().clone(),
        }
    }
    pub fn inbound(&self) -> Value {
        json!({"type":"trojan","tag":"trojan","listen":"127.0.0.1:0","users":[{"name":"test","password":PASSWORD}],"certificate":self.dir.path().join("cert.pem"),"private_key":self.dir.path().join("key.pem")})
    }
    pub async fn connect_alpn(&self, addr: SocketAddr, alpn: &[&[u8]]) -> TlsStream<TcpStream> {
        self.try_connect_alpn(addr, alpn).await.unwrap()
    }

    /// 与 [`Self::connect_alpn`] 相同，但把握手失败作为错误返回，供负向断言使用。
    pub async fn try_connect_alpn(
        &self,
        addr: SocketAddr,
        alpn: &[&[u8]],
    ) -> std::io::Result<TlsStream<TcpStream>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.der.clone()).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
        let stream = TcpStream::connect(addr).await.unwrap();
        timeout(
            Duration::from_secs(3),
            TlsConnector::from(Arc::new(config)).connect("localhost".try_into().unwrap(), stream),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS 握手超时"))?
    }

    pub async fn connect(&self, addr: SocketAddr) -> TlsStream<TcpStream> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.der.clone()).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let stream = TcpStream::connect(addr).await.unwrap();
        timeout(
            Duration::from_secs(3),
            TlsConnector::from(Arc::new(config)).connect("localhost".try_into().unwrap(), stream),
        )
        .await
        .unwrap()
        .unwrap()
    }
}
pub struct Running {
    pub address: SocketAddr,
    pub addresses: Vec<SocketAddr>,
    pub api_address: Option<SocketAddr>,
    pub stats: Arc<Stats>,
    stop: CancellationToken,
    task: Option<JoinHandle<anyhow::Result<()>>>,
}
impl Running {
    pub async fn start(value: Value) -> Self {
        let config = Config::from_json(&value.to_string()).unwrap();
        let tags: Vec<_> = config.inbounds.iter().map(|x| x.tag().to_owned()).collect();
        let server = Server::bind(config).await.unwrap();
        let addresses: Vec<_> = tags
            .iter()
            .map(|tag| server.local_addr(tag).unwrap())
            .collect();
        let stats = server.stats();
        let api_address = server.api_addr();
        let stop = CancellationToken::new();
        let task = tokio::spawn(server.run(stop.clone()));
        Self {
            address: addresses[0],
            addresses,
            api_address,
            stats,
            stop,
            task: Some(task),
        }
    }
    /// 只发出stop信号，用于验证排空期间的行为；调用方负责后续shutdown。
    pub fn stop_now(&self) {
        self.stop.cancel();
    }

    pub async fn shutdown(mut self) {
        self.stop.cancel();
        timeout(SHUTDOWN_TIMEOUT, self.task.as_mut().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        self.task.take();
        let s = self.stats.snapshot();
        assert_eq!(s.connections, 0);
        assert_eq!(s.tcp_flows, 0);
        assert_eq!(s.udp_associations, 0);
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
pub struct Echo {
    pub address: SocketAddr,
    task: JoinHandle<()>,
}
impl Echo {
    pub async fn tcp(ip: &str, after_eof: bool) -> Self {
        let listener = TcpListener::bind(format!("{ip}:0")).await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=>{let (mut s,_)=accepted.unwrap();tasks.spawn(async move {
                        if after_eof {let mut b=Vec::new();s.read_to_end(&mut b).await.unwrap();s.write_all(&b).await.unwrap();s.shutdown().await.unwrap();}
                        else {let (mut r,mut w)=s.split();let _=tokio::io::copy(&mut r,&mut w).await;}
                    });},
                    _=tasks.join_next(),if !tasks.is_empty()=>{}
                }
            }
        });
        Self { address, task }
    }
    pub async fn udp(ip: &str) -> Self {
        let socket = UdpSocket::bind(format!("{ip}:0")).await.unwrap();
        let address = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut b = vec![0; 65536];
            while let Ok((n, p)) = socket.recv_from(&mut b).await {
                socket.send_to(&b[..n], p).await.unwrap();
            }
        });
        Self { address, task }
    }
}
impl Drop for Echo {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// 独立测试端编码，不调用服务端编解码实现。
pub fn address(addr: SocketAddr) -> Vec<u8> {
    let mut b = Vec::new();
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            b.push(1);
            b.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            b.push(4);
            b.extend(ip.octets());
        }
    }
    b.extend(addr.port().to_be_bytes());
    b
}
pub fn domain(name: &str, port: u16) -> Vec<u8> {
    let mut b = vec![3, name.len() as u8];
    b.extend(name.as_bytes());
    b.extend(port.to_be_bytes());
    b
}
/// 读完整的 SOCKS5 应答，返回回复码与 BND 地址。
///
/// **必须读完**：SOCKS5 应答是变长的（4 字节头 + 地址 + 2 字节端口）。
/// 只读前 3～4 字节会让剩余地址留在缓冲区里，被后续读取误当成业务数据——
/// 这个坑在 `tcp_denied`、反向 Bridge 与 geosite 用例里各踩过一次。
pub async fn read_socks_reply<R: AsyncRead + Unpin>(r: &mut R) -> (u8, SocketAddr) {
    let mut head = [0u8; 4];
    read_exact(r, &mut head).await;
    assert_eq!(head[0], 5, "无效 SOCKS 回复");
    let code = head[1];
    // 地址类型：1=IPv4、4=IPv6、3=域名。域名要先读长度。
    let bound = match head[3] {
        1 => {
            let mut b = [0; 4];
            read_exact(r, &mut b).await;
            let port = r.read_u16().await.unwrap();
            SocketAddr::new(std::net::IpAddr::from(b), port)
        }
        4 => {
            let mut b = [0; 16];
            read_exact(r, &mut b).await;
            let port = r.read_u16().await.unwrap();
            SocketAddr::new(std::net::IpAddr::from(b), port)
        }
        3 => {
            let mut length = [0u8; 1];
            read_exact(r, &mut length).await;
            let mut name = vec![0u8; usize::from(length[0])];
            read_exact(r, &mut name).await;
            // 域名形式的 BND 无法转成 SocketAddr；返回未指定地址。
            let _port = r.read_u16().await.unwrap();
            SocketAddr::from(([0, 0, 0, 0], 0))
        }
        other => panic!("无效 SOCKS BND 地址类型 {other}"),
    };
    (code, bound)
}

pub async fn socks(command: u8, target: Vec<u8>, addr: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    read_exact(&mut s, &mut reply).await;
    assert_eq!(reply, [5, 0]);
    let mut request = vec![5, command, 0];
    request.extend(target);
    s.write_all(&request).await.unwrap();
    let (code, bound) = read_socks_reply(&mut s).await;
    assert_eq!(code, 0, "SOCKS 拒绝：code={code}");
    (s, bound)
}
pub async fn read_address<R: AsyncRead + Unpin>(r: &mut R) -> SocketAddr {
    let kind = r.read_u8().await.unwrap();
    let ip = match kind {
        1 => {
            let mut b = [0; 4];
            read_exact(r, &mut b).await;
            std::net::IpAddr::from(b)
        }
        4 => {
            let mut b = [0; 16];
            read_exact(r, &mut b).await;
            std::net::IpAddr::from(b)
        }
        _ => panic!("unexpected address"),
    };
    let port = r.read_u16().await.unwrap();
    SocketAddr::new(ip, port)
}
/// 读满 `b`，超过上限视为测试失败。
///
/// 上限是「多久之内必须收到数据」，不是性能断言。原来的 3 秒在负载高的
/// 机器上会被击穿（本机 load average 19 时 `xray_vless_reality_authentication`
/// 间歇在 4.4 秒处失败，同一命令连跑多次结果不一致），共享 CI runner 上
/// 更不可靠。放宽到 10 秒仍能捕获真正的挂起。
pub async fn read_exact<R: AsyncRead + Unpin>(r: &mut R, b: &mut [u8]) {
    timeout(Duration::from_secs(10), r.read_exact(b))
        .await
        .unwrap()
        .unwrap();
}
pub async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, data: &[u8]) {
    s.write_all(data).await.unwrap();
    let mut b = vec![0; data.len()];
    read_exact(s, &mut b).await;
    assert_eq!(b, data);
}
pub fn trojan_header(command: u8, target: Vec<u8>, password: &str) -> Vec<u8> {
    use sha2::{Digest, Sha224};
    let hash = Sha224::digest(password.as_bytes());
    let mut b = format!("{hash:x}\r\n").into_bytes();
    b.push(command);
    b.extend(target);
    b.extend(b"\r\n");
    b
}
pub fn trojan_udp(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut b = address(addr);
    b.extend((payload.len() as u16).to_be_bytes());
    b.extend(b"\r\n");
    b.extend(payload);
    b
}
pub async fn trojan_recv<S: AsyncRead + Unpin>(s: &mut S) -> (SocketAddr, Vec<u8>) {
    let address = read_address(s).await;
    let len = s.read_u16().await.unwrap();
    let mut crlf = [0; 2];
    read_exact(s, &mut crlf).await;
    assert_eq!(crlf, *b"\r\n");
    let mut data = vec![0; len as usize];
    read_exact(s, &mut data).await;
    (address, data)
}

/// 被测 `dubhe` 可执行文件路径。
///
/// 默认用 Cargo 编译出的二进制；跨平台交叉测试（例如把测试二进制单独
/// 拷到另一台机器）可用 `DUBHE_TEST_BINARY` 指定实际路径，因为
/// `CARGO_BIN_EXE_dubhe` 是**编译时**写死的绝对路径。
pub fn test_binary() -> std::path::PathBuf {
    std::env::var_os("DUBHE_TEST_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_dubhe").into())
}
