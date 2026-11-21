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

pub fn socks_config() -> Value {
    json!({"version":1,"inbounds":[{"type":"socks5","tag":"socks","listen":"127.0.0.1:0"}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"reject","tag":"reject"}],"route":{"default":"direct"},"limits":{"shutdown_timeout_ms":100,"handshake_timeout_ms":300,"udp_idle_timeout_ms":500}})
}
pub struct Certificate {
    pub dir: tempfile::TempDir,
    pub der: rustls::pki_types::CertificateDer<'static>,
}
impl Certificate {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(dir.path().join("cert.pem"), certified.cert.pem()).unwrap();
        let key = dir.path().join("key.pem");
        std::fs::write(&key, certified.key_pair.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self {
            dir,
            der: certified.cert.der().clone(),
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
        timeout(Duration::from_secs(3), self.task.as_mut().unwrap())
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
pub async fn socks(command: u8, target: Vec<u8>, addr: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0; 2];
    read_exact(&mut s, &mut reply).await;
    assert_eq!(reply, [5, 0]);
    let mut request = vec![5, command, 0];
    request.extend(target);
    s.write_all(&request).await.unwrap();
    let mut head = [0; 3];
    read_exact(&mut s, &mut head).await;
    assert_eq!(head, [5, 0, 0]);
    let bound = read_address(&mut s).await;
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
pub async fn read_exact<R: AsyncRead + Unpin>(r: &mut R, b: &mut [u8]) {
    timeout(Duration::from_secs(3), r.read_exact(b))
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
