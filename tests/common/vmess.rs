//! 独立的回环测试端；不调用内核 VMess 编解码/派生接口，不是产品客户端。
#![allow(dead_code)]
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, Payload},
};
use chacha20poly1305::ChaCha20Poly1305;
use cryptoxide::{digest::Digest as OldDigest, hmac::Hmac, mac::Mac};
use md5::{Digest, Md5};
use shake::{
    Shake128, Shake128Reader,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::{
    io,
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

pub const UUID: &str = "11111111-1111-4111-8111-111111111111";
pub const ID: [u8; 16] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];
static NEXT: AtomicU64 = AtomicU64::new(1);

// 每层HMAC由库完成；SHA256克隆后读取避免消耗Digest对象。
enum Hash {
    Sha(sha2::Sha256),
    Mac(Box<Hmac<Hash>>),
}
impl OldDigest for Hash {
    fn input(&mut self, b: &[u8]) {
        match self {
            Self::Sha(h) => sha2::Digest::update(h, b),
            Self::Mac(h) => h.input(b),
        }
    }
    fn result(&mut self, b: &mut [u8]) {
        match self {
            Self::Sha(h) => b[..32].copy_from_slice(&sha2::Digest::finalize(h.clone())),
            Self::Mac(h) => h.raw_result(b),
        }
    }
    fn reset(&mut self) {
        match self {
            Self::Sha(h) => sha2::Digest::reset(h),
            Self::Mac(h) => h.reset(),
        }
    }
    fn block_size(&self) -> usize {
        64
    }
    fn output_bits(&self) -> usize {
        256
    }
}
fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut h = Hash::Mac(Box::new(Hmac::new(
        Hash::Sha(sha2::Sha256::default()),
        b"VMess AEAD KDF",
    )));
    for p in path {
        h = Hash::Mac(Box::new(Hmac::new(h, p)));
    }
    h.input(key);
    let mut b = [0; 32];
    h.result(&mut b);
    b
}
fn short(b: &[u8]) -> [u8; 16] {
    b[..16].try_into().unwrap()
}
fn response(b: &[u8]) -> [u8; 16] {
    short(&<sha2::Sha256 as sha2::Digest>::digest(b))
}
fn aead(
    security: u8,
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    b: &[u8],
    encrypt: bool,
) -> Vec<u8> {
    let p = Payload { msg: b, aad };
    match security {
        3 => {
            let c = Aes128Gcm::new(key.into());
            if encrypt {
                c.encrypt(nonce.into(), p)
            } else {
                c.decrypt(nonce.into(), p)
            }
        }
        4 => {
            let first = Md5::digest(key);
            let mut expanded = [0; 32];
            expanded[..16].copy_from_slice(&first);
            expanded[16..].copy_from_slice(&Md5::digest(first));
            let c = ChaCha20Poly1305::new((&expanded).into());
            if encrypt {
                c.encrypt(nonce.into(), p)
            } else {
                c.decrypt(nonce.into(), p)
            }
        }
        _ => panic!("测试端AEAD安全值"),
    }
    .expect("独立测试端AEAD验证")
}
pub fn target(addr: SocketAddr) -> Vec<u8> {
    let mut b = addr.port().to_be_bytes().to_vec();
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            b.push(1);
            b.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            b.push(3);
            b.extend(ip.octets());
        }
    }
    b
}
pub fn domain(name: &str, port: u16) -> Vec<u8> {
    let mut b = port.to_be_bytes().to_vec();
    b.extend([2, name.len() as u8]);
    b.extend(name.as_bytes());
    b
}
pub fn packetaddr(addr: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut b = vec![];
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            b.push(1);
            b.extend(ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            b.push(2);
            b.extend(ip.octets());
        }
    }
    b.extend(addr.port().to_be_bytes());
    b.extend(data);
    b
}
#[derive(Clone)]
pub struct Request {
    pub wire: Vec<u8>,
    pub key: [u8; 16],
    pub iv: [u8; 16],
    pub security: u8,
    pub options: u8,
    auth: u8,
}
impl Request {
    pub fn new(command: u8, target: Vec<u8>, security: u8, options: u8) -> Self {
        Self::at(
            command,
            target,
            security,
            options,
            ID,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            None,
        )
    }
    pub fn at(
        command: u8,
        target: Vec<u8>,
        security: u8,
        options: u8,
        uuid: [u8; 16],
        timestamp: u64,
        session: Option<([u8; 16], [u8; 16])>,
    ) -> Self {
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let seed = <sha2::Sha256 as sha2::Digest>::digest(serial.to_be_bytes());
        let (key, iv) = session.unwrap_or_else(|| (short(&seed), seed[16..].try_into().unwrap()));
        let mut cmd = uuid.to_vec();
        cmd.extend(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let cmd: [u8; 16] = Md5::digest(&cmd).into();
        let mut id = [0; 16];
        id[..8].copy_from_slice(&timestamp.to_be_bytes());
        id[8..12].copy_from_slice(&(serial as u32).to_be_bytes());
        let crc = crc32fast::hash(&id[..12]);
        id[12..].copy_from_slice(&crc.to_be_bytes());
        let mut block = id.into();
        aes::Aes128::new((&short(&kdf(&cmd, &[b"AES Auth ID Encryption"]))).into())
            .encrypt_block(&mut block);
        let id: [u8; 16] = block.into();
        let auth = 0x53;
        let mut inner = vec![1];
        inner.extend(iv);
        inner.extend(key);
        inner.extend([auth, options, security, 0, command]);
        inner.extend(target);
        let fnv = inner.iter().fold(0x811c9dc5u32, |h, b| {
            (h ^ u32::from(*b)).wrapping_mul(0x01000193)
        });
        inner.extend(fnv.to_be_bytes());
        let connection_nonce = serial.to_be_bytes();
        let mut wire = id.to_vec();
        for (kl, nl, data) in [
            (
                b"VMess Header AEAD Key_Length".as_slice(),
                b"VMess Header AEAD Nonce_Length".as_slice(),
                (inner.len() as u16).to_be_bytes().to_vec(),
            ),
            (
                b"VMess Header AEAD Key".as_slice(),
                b"VMess Header AEAD Nonce".as_slice(),
                inner,
            ),
        ] {
            let key = short(&kdf(&cmd, &[kl, &id, &connection_nonce]));
            let nonce: [u8; 12] = kdf(&cmd, &[nl, &id, &connection_nonce])[..12]
                .try_into()
                .unwrap();
            wire.extend(aead(3, &key, &nonce, &id, &data, true));
            if wire.len() == 34 {
                wire.extend(connection_nonce);
            }
        }
        Self {
            wire,
            key,
            iv,
            security,
            options,
            auth,
        }
    }
}
struct Body {
    key: [u8; 16],
    iv: [u8; 16],
    request_key: [u8; 16],
    request_iv: [u8; 16],
    security: u8,
    options: u8,
    counter: u32,
    shake: Shake128Reader,
}
impl Body {
    fn new(r: &Request, down: bool) -> Self {
        let key = if down { response(&r.key) } else { r.key };
        let iv = if down { response(&r.iv) } else { r.iv };
        let mut s = Shake128::default();
        Update::update(&mut s, &iv);
        Self {
            key,
            iv,
            request_key: r.key,
            request_iv: r.iv,
            security: r.security,
            options: r.options,
            counter: 0,
            shake: s.finalize_xof(),
        }
    }
    fn raw(&self) -> bool {
        self.security == 5 && self.options == 0
    }
    fn nonce(&self, iv: &[u8; 16]) -> [u8; 12] {
        let mut n = [0; 12];
        n[..2].copy_from_slice(&u16::try_from(self.counter).unwrap().to_be_bytes());
        n[2..].copy_from_slice(&iv[2..12]);
        n
    }
    fn layout(&mut self) -> (usize, u16) {
        let mut word = || {
            let mut b = [0; 2];
            self.shake.read(&mut b);
            u16::from_be_bytes(b)
        };
        let p = if self.options & 8 != 0 {
            usize::from(word() % 64)
        } else {
            0
        };
        let m = if self.options & 4 != 0 && self.options & 16 == 0 {
            word()
        } else {
            0
        };
        (p, m)
    }
    fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        if self.raw() {
            return data.to_vec();
        }
        let (padding, mask) = self.layout();
        let crypt = self.security != 5;
        let body = if crypt {
            aead(
                self.security,
                &self.key,
                &self.nonce(&self.iv),
                &[],
                data,
                true,
            )
        } else {
            data.to_vec()
        };
        let length = data.len()
            + padding
            + if crypt && self.options & 16 == 0 {
                16
            } else {
                0
            };
        let length = u16::try_from(length).unwrap();
        let mut wire = if self.options & 16 != 0 {
            aead(
                self.security,
                &short(&kdf(&self.request_key, &[b"auth_len"])),
                &self.nonce(&self.request_iv),
                &[],
                &length.to_be_bytes(),
                true,
            )
        } else {
            (length ^ mask).to_be_bytes().to_vec()
        };
        wire.extend(body);
        wire.resize(wire.len() + padding, 0xa6);
        if crypt {
            self.counter += 1;
        }
        wire
    }
    async fn read<S: AsyncRead + Unpin>(&mut self, s: &mut S) -> Vec<u8> {
        assert!(!self.raw());
        let (padding, mask) = self.layout();
        let mut h = vec![0; if self.options & 16 != 0 { 18 } else { 2 }];
        exact(s, &mut h).await;
        let length = if self.options & 16 != 0 {
            let v = aead(
                self.security,
                &short(&kdf(&self.request_key, &[b"auth_len"])),
                &self.nonce(&self.request_iv),
                &[],
                &h,
                false,
            );
            usize::from(u16::from_be_bytes(v.try_into().unwrap())) + 16
        } else {
            usize::from(u16::from_be_bytes(h.try_into().unwrap()) ^ mask)
        };
        assert!(length >= padding);
        let mut b = vec![0; length];
        exact(s, &mut b).await;
        b.truncate(length - padding);
        if self.security == 5 {
            b
        } else {
            let b = aead(
                self.security,
                &self.key,
                &self.nonce(&self.iv),
                &[],
                &b,
                false,
            );
            self.counter += 1;
            b
        }
    }
}
async fn exact<S: AsyncRead + Unpin>(s: &mut S, b: &mut [u8]) {
    timeout(Duration::from_secs(3), s.read_exact(b))
        .await
        .expect("VMess读取超时")
        .unwrap();
}
pub struct Client<S> {
    pub io: S,
    tx: Body,
    rx: Body,
    pending: Vec<u8>,
}
impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    pub async fn start(mut io: S, r: Request, first: Option<&[u8]>) -> Self {
        let mut tx = Body::new(&r, false);
        let mut wire = r.wire.clone();
        if let Some(data) = first {
            wire.extend(tx.encode(data));
        }
        io.write_all(&wire).await.unwrap();
        io.flush().await.unwrap();
        let key = response(&r.key);
        let iv = response(&r.iv);
        let mut header = [0; 18];
        exact(&mut io, &mut header).await;
        let nonce: [u8; 12] = kdf(&iv, &[b"AEAD Resp Header Len IV"])[..12]
            .try_into()
            .unwrap();
        let size = aead(
            3,
            &short(&kdf(&key, &[b"AEAD Resp Header Len Key"])),
            &nonce,
            &[],
            &header,
            false,
        );
        assert_eq!(size, [0, 4]);
        let mut header = [0; 20];
        exact(&mut io, &mut header).await;
        let nonce: [u8; 12] = kdf(&iv, &[b"AEAD Resp Header IV"])[..12]
            .try_into()
            .unwrap();
        assert_eq!(
            aead(
                3,
                &short(&kdf(&key, &[b"AEAD Resp Header Key"])),
                &nonce,
                &[],
                &header,
                false
            ),
            [r.auth, 0, 0, 0]
        );
        Self {
            io,
            tx,
            rx: Body::new(&r, true),
            pending: vec![],
        }
    }
    pub fn wire(&mut self, data: &[u8]) -> Vec<u8> {
        self.tx.encode(data)
    }
    pub async fn send(&mut self, data: &[u8]) {
        let wire = self.tx.encode(data);
        self.io.write_all(&wire).await.unwrap();
        self.io.flush().await.unwrap();
    }
    pub async fn recv(&mut self) -> Vec<u8> {
        self.rx.read(&mut self.io).await
    }
    pub async fn read(&mut self, n: usize) -> Vec<u8> {
        if self.rx.raw() {
            let mut b = vec![0; n];
            exact(&mut self.io, &mut b).await;
            return b;
        }
        while self.pending.len() < n {
            let b = self.recv().await;
            assert!(!b.is_empty(), "过早VMess终止块");
            self.pending.extend(b);
        }
        self.pending.drain(..n).collect()
    }
    pub async fn finish(&mut self) {
        if !self.tx.raw() {
            self.send(&[]).await;
        }
        self.io.shutdown().await.unwrap();
    }
    pub async fn eof(&mut self) {
        if !self.rx.raw() {
            assert!(self.recv().await.is_empty());
        } else {
            let mut b = [0];
            assert_eq!(
                timeout(Duration::from_secs(3), self.io.read(&mut b))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
    }
}
/// 路由拒绝前可能已写出协议应答；只要求连接最终结束。
pub async fn closed_after_optional_response<S: AsyncRead + Unpin>(s: &mut S) {
    let mut sink = Vec::new();
    let _ = timeout(Duration::from_secs(2), s.read_to_end(&mut sink)).await;
}
pub async fn closed<S: AsyncRead + Unpin>(s: &mut S) {
    let mut b = [0];
    assert!(matches!(
        timeout(Duration::from_secs(2), s.read(&mut b))
            .await
            .unwrap(),
        Ok(0) | Err(_)
    ));
}
pub fn xframe(
    id: u16,
    status: u8,
    address: Option<Vec<u8>>,
    global: bool,
    data: Option<&[u8]>,
) -> Vec<u8> {
    xframe_global(id, status, address, global.then_some([0x77; 8]), data)
}
// GlobalID 是进程级键；并行测试必须使用互不相同的值，避免相互接管。
pub fn xframe_gid(
    id: u16,
    status: u8,
    address: Option<Vec<u8>>,
    global: [u8; 8],
    data: Option<&[u8]>,
) -> Vec<u8> {
    xframe_global(id, status, address, Some(global), data)
}
fn xframe_global(
    id: u16,
    status: u8,
    address: Option<Vec<u8>>,
    global: Option<[u8; 8]>,
    data: Option<&[u8]>,
) -> Vec<u8> {
    let mut m = id.to_be_bytes().to_vec();
    m.extend([status, u8::from(data.is_some())]);
    if let Some(a) = address {
        m.push(2);
        m.extend(a);
    }
    if let Some(global) = global {
        m.extend(global);
    }
    let mut b = (m.len() as u16).to_be_bytes().to_vec();
    b.extend(m);
    if let Some(d) = data {
        b.extend((d.len() as u16).to_be_bytes());
        b.extend(d);
    }
    b
}
pub async fn xrecv<S: AsyncRead + AsyncWrite + Unpin>(c: &mut Client<S>) -> (Vec<u8>, Vec<u8>) {
    let n = u16::from_be_bytes(c.read(2).await.try_into().unwrap());
    assert!((4..=512).contains(&n));
    let m = c.read(n as usize).await;
    let b = if m[3] & 1 != 0 {
        let n = u16::from_be_bytes(c.read(2).await.try_into().unwrap());
        c.read(n as usize).await
    } else {
        vec![]
    };
    (m, b)
}
pub async fn xexpect<S: AsyncRead + AsyncWrite + Unpin>(
    c: &mut Client<S>,
    id: u16,
    addr: SocketAddr,
    data: &[u8],
) {
    let (m, b) = xrecv(c).await;
    let mut expected = id.to_be_bytes().to_vec();
    expected.extend([2, 1, 2]);
    expected.extend(target(addr));
    assert_eq!(m, expected);
    assert_eq!(b, data);
}
pub fn error_kind(e: io::Error) -> io::ErrorKind {
    e.kind()
}
