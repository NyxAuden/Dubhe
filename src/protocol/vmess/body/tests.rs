use super::*;
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit},
};
use chacha20poly1305::ChaCha20Poly1305;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const IV: [u8; 16] = [
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
const PAYLOAD: &[u8] = b"\x00VMess\xff\x01";

fn hex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn array<const N: usize>(input: &str) -> [u8; N] {
    hex(input).try_into().unwrap()
}

// 以下材料来自独立 Python3 标准库 hashlib/hmac（非生产 crypto helper）。
// KDF = HMAC(HMAC(SHA256, "VMess AEAD KDF"), "auth_len")(KEY)[:16]；
// 下行 key/IV = SHA256(KEY/IV)[:16]，ChaCha = MD5(k)||MD5(MD5(k))。
fn response_key() -> [u8; 16] {
    array("be45cb2605bf36bebde684841a28f0fd")
}
fn response_iv() -> [u8; 16] {
    array("fc2e2c73072bfa2bda03ff9307472deb")
}
fn length_key() -> [u8; 16] {
    array("1dccf11d87f6b6c6ffbaa5b90794383c")
}

fn reference_nonce(counter: u16, iv: &[u8; 16]) -> [u8; 12] {
    [counter.to_be_bytes().as_slice(), &iv[2..12]]
        .concat()
        .try_into()
        .unwrap()
}

// 独立测试端直接使用成熟 AEAD/MD5 API，不调用 Cipher 或正文编码器。
fn reference_key(key: &[u8; 16]) -> [u8; 32] {
    use md5::{Digest, Md5};
    let first = Md5::digest(key);
    let second = Md5::digest(first);
    [first.as_slice(), second.as_slice()]
        .concat()
        .try_into()
        .unwrap()
}
fn seal(security: u8, key: &[u8; 16], iv: &[u8; 16], counter: u16, bytes: &[u8]) -> Vec<u8> {
    let nonce = reference_nonce(counter, iv);
    match security {
        3 => Aes128Gcm::new(key.into())
            .encrypt((&nonce).into(), bytes)
            .unwrap(),
        4 => ChaCha20Poly1305::new((&reference_key(key)).into())
            .encrypt((&nonce).into(), bytes)
            .unwrap(),
        5 => bytes.to_vec(),
        _ => unreachable!(),
    }
}
fn open(security: u8, key: &[u8; 16], iv: &[u8; 16], counter: u16, bytes: &[u8]) -> Vec<u8> {
    let nonce = reference_nonce(counter, iv);
    match security {
        3 => Aes128Gcm::new(key.into())
            .decrypt((&nonce).into(), bytes)
            .unwrap(),
        4 => ChaCha20Poly1305::new((&reference_key(key)).into())
            .decrypt((&nonce).into(), bytes)
            .unwrap(),
        5 => bytes.to_vec(),
        _ => unreachable!(),
    }
}

struct Reference {
    security: u8,
    options: u8,
    key: [u8; 16],
    iv: [u8; 16],
    shake: Shake128Reader,
    counter: u16,
}
impl Reference {
    fn new(security: u8, options: u8, response: bool) -> Self {
        let iv = if response { response_iv() } else { IV };
        let key = if response { response_key() } else { KEY };
        let mut hash = Shake128::default();
        hash.update(&iv);
        Self {
            security,
            options,
            key,
            iv,
            shake: hash.finalize_xof(),
            counter: 0,
        }
    }
    fn layout(&mut self) -> (usize, u16) {
        let mut next = || {
            let mut bytes = [0; 2];
            self.shake.read(&mut bytes);
            u16::from_be_bytes(bytes)
        };
        let padding = if self.options & 8 != 0 {
            (next() % 64) as usize
        } else {
            0
        };
        let mask = if self.options & 4 != 0 && self.options & 16 == 0 {
            next()
        } else {
            0
        };
        (padding, mask)
    }
    fn frame(&mut self, payload: &[u8]) -> Vec<u8> {
        let (padding, mask) = self.layout();
        let body = seal(self.security, &self.key, &self.iv, self.counter, payload);
        let mut output = if self.options & 16 != 0 {
            seal(
                self.security,
                &length_key(),
                &IV,
                self.counter,
                &((payload.len() + padding) as u16).to_be_bytes(),
            )
        } else {
            (((body.len() + padding) as u16) ^ mask)
                .to_be_bytes()
                .to_vec()
        };
        output.extend(body);
        output.extend(std::iter::repeat_n(0xa5, padding));
        self.counter = self.counter.wrapping_add(1);
        output
    }
    fn decode(&mut self, wire: &[u8]) -> (Vec<u8>, usize) {
        let (padding, mask) = self.layout();
        let header = if self.options & 16 != 0 { 18 } else { 2 };
        let body_length = if header == 18 {
            let bytes = open(self.security, &length_key(), &IV, self.counter, &wire[..18]);
            usize::from(u16::from_be_bytes(bytes.try_into().unwrap())) + 16
        } else {
            usize::from(u16::from_be_bytes(wire[..2].try_into().unwrap()) ^ mask)
        };
        let payload = open(
            self.security,
            &self.key,
            &self.iv,
            self.counter,
            &wire[header..header + body_length - padding],
        );
        self.counter = self.counter.wrapping_add(1);
        (payload, header + body_length)
    }
}

#[derive(Default)]
struct State {
    output: Vec<u8>,
    read: usize,
    read_limit: usize,
    blocked_write: bool,
    write_calls: usize,
    flushed: usize,
    shutdowns: usize,
}
struct Controlled {
    input: Vec<u8>,
    state: Arc<Mutex<State>>,
    chunk: usize,
    alternate: bool,
    read_pending: bool,
    write_pending: bool,
    flush_pending: bool,
    shutdown_pending: bool,
    read_error: Option<io::ErrorKind>,
    write_error: Option<io::ErrorKind>,
    zero_write: bool,
}
impl Controlled {
    fn new(input: Vec<u8>, chunk: usize, alternate: bool) -> (Self, Arc<Mutex<State>>) {
        let state = Arc::new(Mutex::new(State {
            read_limit: usize::MAX,
            ..State::default()
        }));
        (
            Self {
                input,
                state: state.clone(),
                chunk,
                alternate,
                read_pending: false,
                write_pending: false,
                flush_pending: false,
                shutdown_pending: false,
                read_error: None,
                write_error: None,
                zero_write: false,
            },
            state,
        )
    }
    fn pend(alternate: bool, pending: &mut bool, cx: &Context<'_>) -> bool {
        if !alternate {
            return false;
        }
        *pending = !*pending;
        if *pending {
            cx.waker().wake_by_ref();
            true
        } else {
            false
        }
    }
}
impl AsyncRead for Controlled {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if Self::pend(this.alternate, &mut this.read_pending, cx) {
            return Poll::Pending;
        }
        let mut state = this.state.lock().unwrap();
        if state.read >= state.read_limit {
            return Poll::Pending;
        }
        if state.read == this.input.len() {
            return Poll::Ready(match this.read_error {
                Some(kind) => Err(io::Error::new(kind, "受控读取错误")),
                None => Ok(()),
            });
        }
        let count = buffer
            .remaining()
            .min(this.chunk)
            .min(this.input.len() - state.read)
            .min(state.read_limit - state.read);
        buffer.put_slice(&this.input[state.read..state.read + count]);
        state.read += count;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Controlled {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if Self::pend(this.alternate, &mut this.write_pending, cx) {
            return Poll::Pending;
        }
        let mut state = this.state.lock().unwrap();
        state.write_calls += 1;
        if state.blocked_write {
            return Poll::Pending;
        }
        if let Some(kind) = this.write_error {
            return Poll::Ready(Err(io::Error::new(kind, "受控写入错误")));
        }
        if this.zero_write {
            return Poll::Ready(Ok(0));
        }
        let count = bytes.len().min(this.chunk);
        state.output.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if Self::pend(this.alternate, &mut this.flush_pending, cx) {
            return Poll::Pending;
        }
        this.state.lock().unwrap().flushed += 1;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if Self::pend(this.alternate, &mut this.shutdown_pending, cx) {
            return Poll::Pending;
        }
        this.state.lock().unwrap().shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}

fn receive_codec(security: u8, options: u8) -> Codec {
    Codec::new(security, options, &KEY, &IV, &KEY, &IV).unwrap()
}
fn send_codec(security: u8, options: u8) -> Codec {
    Codec::new(
        security,
        options,
        &response_key(),
        &response_iv(),
        &KEY,
        &IV,
    )
    .unwrap()
}
fn context() -> Context<'static> {
    Context::from_waker(std::task::Waker::noop())
}

// 固定金样来源：Python3 cryptography.hazmat.primitives.ciphers.aead AESGCM /
// ChaCha20Poly1305 + hashlib/hmac；公开凭据 KEY=00..0f、IV=10..1f、
// payload=00 56 4d 65 73 73 ff 01。这里保存完整 hex，而非运行生产 codec 后期望自洽。
const VECTORS: [(u8, &str, &str, &str, &str); 2] = [
    (
        3,
        "0018cb25e5dc9ac24f7f0bfe113d7888fcfd955b5b0d13c4ad6f",
        "00180ad0624db51bc8db4be6cb4758c746d71f52b93c8af8d9dd",
        "18913639fade7fa8394369f431eff5317e98cb25e5dc9ac24f7f0bfe113d7888fcfd955b5b0d13c4ad6f",
        "18913639fade7fa8394369f431eff5317e980ad0624db51bc8db4be6cb4758c746d71f52b93c8af8d9dd",
    ),
    (
        4,
        "0018bfc5475f182f7cb9767aadfe936b686a26190297eda26882",
        "001882026fa0d3cd0f3f2b700f71f3624e9f8e91bf124760b006",
        "43cdef6dc88c5d374620495906cbde951bfbbfc5475f182f7cb9767aadfe936b686a26190297eda26882",
        "43cdef6dc88c5d374620495906cbde951bfb82026fa0d3cd0f3f2b700f71f3624e9f8e91bf124760b006",
    ),
];

#[tokio::test]
async fn independent_python_vectors_both_directions_and_c_bit() {
    for (security, request, response, request_auth, response_auth) in VECTORS {
        for options in [0, 1, 16, 17, 20, 21] {
            let authenticated = options & 16 != 0;
            let request = hex(if authenticated { request_auth } else { request });
            let response = hex(if authenticated {
                response_auth
            } else {
                response
            });
            let (io, state) = Controlled::new(request.clone(), 1, true);
            let (mut reader, mut writer) = split(io, security, options, KEY, IV).unwrap();
            assert_eq!(reader.packet().await.unwrap().unwrap(), PAYLOAD);
            assert!(reader.packet().await.unwrap().is_none());
            writer.packet(PAYLOAD).await.unwrap();
            assert_eq!(state.lock().unwrap().output, response);
            let mut ref_request = Reference::new(security, options, false);
            assert_eq!(ref_request.frame(PAYLOAD), request);
            let mut ref_response = Reference::new(security, options, true);
            assert_eq!(ref_response.frame(PAYLOAD), response);
        }
    }
    assert_eq!(
        reference_key(&KEY),
        array::<32>("1ac1ef01e96caf1be0d329331a4fc2a8e0542db5418c43d256a6a643afa553fe")
    );
}

#[test]
fn complete_security_options_matrix() {
    for security in 0..=u8::MAX {
        for options in 0..=u8::MAX {
            let allowed = match security {
                3 | 4 => [0, 1, 4, 5, 12, 13, 16, 17, 20, 21, 28, 29].contains(&options),
                5 => options <= 1,
                _ => false,
            };
            assert_eq!(
                Codec::new(security, options, &KEY, &IV, &KEY, &IV).is_ok(),
                allowed,
                "security={security}, options={options}"
            );
        }
    }
}

#[test]
fn shake_full_iv_golden_and_single_sequence_order() {
    // Python hashlib.shake_128(bytes(range(16,32))).digest(32)。
    let expected = hex("fc918e43ecc4b6aea436a3be55984a75e0c01600dfda15041a69c312ea34160f4");
    let codec = receive_codec(3, 13);
    let mut sequence = codec.sequence.clone();
    let mut got = [0; 32];
    sequence.read(&mut got);
    assert_eq!(got.as_slice(), expected);
    let mut sequence = codec.sequence.clone();
    assert_eq!(codec.layout(&mut sequence), (17, 0x8e43));
    assert_eq!(codec.layout(&mut sequence), (4, 0xb6ae));
    let codec = receive_codec(3, 5);
    let mut sequence = codec.sequence.clone();
    assert_eq!(codec.layout(&mut sequence), (0, 0xfc91));
    assert_eq!(codec.layout(&mut sequence), (0, 0x8e43));
    let codec = receive_codec(3, 29);
    let mut sequence = codec.sequence.clone();
    assert_eq!(codec.layout(&mut sequence), (17, 0));
    assert_eq!(codec.layout(&mut sequence), (3, 0)); // A 不消费 mask：第二个值是 0x8e43 % 64。
    let mut other_iv = IV;
    other_iv[15] ^= 1;
    let codec2 = Codec::new(3, 13, &KEY, &other_iv, &KEY, &IV).unwrap();
    let mut different = [0; 32];
    codec2.sequence.clone().read(&mut different);
    assert_ne!(got, different); // 不能只用 nonce 的 IV[2..12] 播种。
}

#[tokio::test]
async fn masks_padding_and_authenticated_length_sequences() {
    for security in [3, 4] {
        for options in [4, 5, 12, 13, 16, 17, 20, 21, 28, 29] {
            let payloads: Vec<Vec<u8>> = (1..=32).map(|n| vec![n as u8; n * 3]).collect();
            let mut reference = Reference::new(security, options, false);
            let mut input = Vec::new();
            for payload in &payloads {
                input.extend(reference.frame(payload));
            }
            input.extend(reference.frame(&[]));
            input.extend(b"must remain unread");
            let (io, state) = Controlled::new(input.clone(), 3, true);
            let mut reader = Reader::new(io, receive_codec(security, options));
            for payload in &payloads {
                assert_eq!(reader.packet().await.unwrap().unwrap(), *payload);
            }
            assert!(reader.packet().await.unwrap().is_none());
            assert!(reader.packet().await.unwrap().is_none());
            assert_eq!(
                state.lock().unwrap().read,
                input.len() - b"must remain unread".len()
            );

            let (io, state) = Controlled::new(Vec::new(), 2, true);
            let mut writer = Writer::new(io, send_codec(security, options));
            for payload in &payloads {
                writer.packet(payload).await.unwrap();
            }
            writer.shutdown().await.unwrap();
            let output = state.lock().unwrap().output.clone();
            let mut reference = Reference::new(security, options, true);
            let mut used = 0;
            for payload in payloads.iter().chain(std::iter::once(&Vec::new())) {
                let (decoded, count) = reference.decode(&output[used..]);
                assert_eq!(&decoded, payload);
                used += count;
            }
            assert_eq!(used, output.len());
        }
    }
}

#[test]
fn padding_covers_every_length_without_authenticating_padding() {
    for security in [3, 4] {
        for options in [12, 13, 28, 29] {
            let mut codec = receive_codec(security, options);
            let mut independent = Reference::new(security, options, false);
            let mut seen = [false; 64];
            for _ in 0..1024 {
                let mut sequence = independent.shake.clone();
                let mut word = [0; 2];
                sequence.read(&mut word);
                let padding = (u16::from_be_bytes(word) % 64) as usize;
                seen[padding] = true;
                let wire = codec.encode(PAYLOAD, false).unwrap();
                let (decoded, count) = independent.decode(&wire);
                assert_eq!(decoded, PAYLOAD);
                assert_eq!(count, wire.len());
            }
            assert!(seen.into_iter().all(|value| value));
        }
        let mut client = Reference::new(security, 13, false);
        let mut wire = client.frame(PAYLOAD);
        // 第一块 P=17；后置随机 padding 不在正文 AEAD tag 的认证范围。
        *wire.last_mut().unwrap() ^= 0xff;
        let mut reader = receive_codec(security, 13);
        let (size, padding) = reader.decode_length(&wire[..2]).unwrap();
        assert_eq!(padding, 17);
        assert_eq!(
            reader.decode_payload(&wire[2..2 + size], padding).unwrap(),
            PAYLOAD
        );
    }
}

#[tokio::test]
async fn maximum_receive_ranges_and_packet_send_does_not_split() {
    for security in [3, 4, 5] {
        for options in if security == 5 {
            vec![1]
        } else {
            vec![0, 1, 4, 5, 12, 13, 16, 17, 20, 21, 28, 29]
        } {
            let mut reference = Reference::new(security, options, false);
            let mut probe = Reference::new(security, options, false);
            let (padding, _) = probe.layout();
            let tag = if security == 5 || options & 16 != 0 {
                0
            } else {
                16
            };
            let maximum = 65535 - padding - tag;
            let payload = vec![0x92; maximum];
            let wire = reference.frame(&payload);
            if options & 16 != 0 && padding == 0 {
                assert_eq!(wire.len() - 18, 65551);
            }
            let (io, _) = Controlled::new(wire, 257, true);
            let mut reader = Reader::new(io, receive_codec(security, options));
            assert_eq!(reader.packet().await.unwrap().unwrap(), payload);
            assert!(reader.packet().await.unwrap().is_none());

            let (io, state) = Controlled::new(Vec::new(), 1024, true);
            let mut writer = Writer::new(io, receive_codec(security, options));
            assert_eq!(
                writer
                    .packet(&vec![0x92; maximum + 1])
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(writer.codec.counter, 0);
            assert!(state.lock().unwrap().output.is_empty());
            writer.packet(&payload).await.unwrap();
            let output = state.lock().unwrap().output.clone();
            let mut reference = Reference::new(security, options, false);
            let (decoded, count) = reference.decode(&output);
            assert_eq!(decoded, payload);
            assert_eq!(count, output.len()); // 不是自动拆成 16KiB 多包。
            assert_eq!(writer.output.len(), 0);
        }
    }
}

#[tokio::test]
async fn empty_terminal_requires_complete_valid_tag_and_stops_before_tail() {
    // NIST SP800-38D 全零 key/nonce、空正文和 AAD 的独立 AES-GCM tag。
    let golden = hex("001058e2fccefa7e3061367f1d57a4e7455a");
    for corrupt in [false, true] {
        let mut input = golden.clone();
        if corrupt {
            *input.last_mut().unwrap() ^= 1;
        }
        input.extend(b"tail");
        let (io, state) = Controlled::new(input, 1, true);
        let codec = Codec::new(3, 0, &[0; 16], &[0; 16], &[0; 16], &[0; 16]).unwrap();
        let mut reader = Reader::new(io, codec);
        let result = reader.packet().await;
        if corrupt {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        } else {
            assert!(result.unwrap().is_none());
        }
        assert_eq!(state.lock().unwrap().read, golden.len());
    }
    for security in [3, 4] {
        for options in [0, 13, 16, 29] {
            let mut reference = Reference::new(security, options, false);
            let terminal = reference.frame(&[]);
            for cut in 1..terminal.len() {
                let (io, _) = Controlled::new(terminal[..cut].to_vec(), 1, true);
                let mut reader = Reader::new(io, receive_codec(security, options));
                assert_eq!(
                    reader.packet().await.unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof,
                    "security={security} options={options} cut={cut}"
                );
            }
        }
    }
}

#[tokio::test]
async fn truncation_bad_tags_and_invalid_lengths_fail_without_plaintext() {
    for security in [3, 4] {
        for options in [0, 5, 13, 16, 29] {
            let mut reference = Reference::new(security, options, false);
            let wire = reference.frame(PAYLOAD);
            for cut in 0..wire.len() {
                let (io, _) = Controlled::new(wire[..cut].to_vec(), 3, true);
                let mut reader = Reader::new(io, receive_codec(security, options));
                if cut == 0 {
                    assert!(reader.packet().await.unwrap().is_none());
                } else {
                    assert_eq!(
                        reader.packet().await.unwrap_err().kind(),
                        io::ErrorKind::UnexpectedEof
                    );
                }
            }
            let mut bad = wire;
            let header = if options & 16 != 0 { 18 } else { 2 };
            bad[header] ^= 1;
            bad.extend(reference.frame(b"cannot resynchronize"));
            let (io, state) = Controlled::new(bad, 1, true);
            let mut reader = Reader::new(io, receive_codec(security, options));
            let mut output = [0x5a; 128];
            assert_eq!(
                reader.read(&mut output).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(output, [0x5a; 128]);
            let consumed = state.lock().unwrap().read;
            assert!(reader.packet().await.is_err());
            assert!(reader.read(&mut output).await.is_err());
            assert_eq!(state.lock().unwrap().read, consumed);
            assert!(reader.wire.is_empty());
            assert!(reader.payload.is_empty());
        }
    }
    for length in 0..16u16 {
        let (io, state) = Controlled::new(length.to_be_bytes().to_vec(), 1, false);
        let mut reader = Reader::new(io, receive_codec(3, 0));
        assert_eq!(
            reader.packet().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(state.lock().unwrap().read, 2);
    }
    // P=17、普通 body 至少 16+17；A 的解密长度至少容纳 17 padding。
    for authenticated in [false, true] {
        let options = if authenticated { 29 } else { 13 };
        let mut wire = if authenticated {
            seal(3, &length_key(), &IV, 0, &16u16.to_be_bytes())
        } else {
            (32u16 ^ 0x8e43).to_be_bytes().to_vec()
        };
        wire.extend(vec![0; 128]);
        let (io, state) = Controlled::new(wire, 1, false);
        let mut reader = Reader::new(io, receive_codec(3, options));
        assert_eq!(
            reader.packet().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            state.lock().unwrap().read,
            if authenticated { 18 } else { 2 }
        );
    }
}

#[tokio::test]
async fn authenticated_length_rejects_bad_tag_before_reading_body() {
    for security in [3, 4] {
        let mut reference = Reference::new(security, 16, false);
        let mut wire = reference.frame(PAYLOAD);
        wire[17] ^= 1;
        let (io, state) = Controlled::new(wire, 1, true);
        let mut reader = Reader::new(io, receive_codec(security, 16));
        assert_eq!(
            reader.packet().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(state.lock().unwrap().read, 18);
        assert!(reader.wire.is_empty());
    }
}

#[tokio::test]
async fn pending_reader_keeps_partial_frame_and_never_delivers_before_tag() {
    for security in [3, 4] {
        for options in [0, 13, 16, 29] {
            let mut reference = Reference::new(security, options, false);
            let wire = reference.frame(PAYLOAD);
            for limit in [1, if options & 16 != 0 { 18 } else { 2 }, wire.len() - 1] {
                let (io, state) = Controlled::new(wire.clone(), 1, false);
                state.lock().unwrap().read_limit = limit;
                let mut reader = Reader::new(io, receive_codec(security, options));
                let mut output = [0x6b; 64];
                let mut buffer = ReadBuf::new(&mut output);
                assert!(
                    Pin::new(&mut reader)
                        .poll_read(&mut context(), &mut buffer)
                        .is_pending()
                );
                assert!(buffer.filled().is_empty());
                assert_eq!(output, [0x6b; 64]);
                assert_eq!(state.lock().unwrap().read, limit);
                // 放弃半帧 read future 后 packet 接口仍复用同一个读取游标。
                state.lock().unwrap().read_limit = usize::MAX;
                assert_eq!(reader.packet().await.unwrap().unwrap(), PAYLOAD);
                assert_eq!(reader.codec.counter, 1);
            }
        }
    }
}

#[tokio::test]
async fn cancelled_packet_future_preserves_header_body_and_output_cursor() {
    let mut reference = Reference::new(3, 29, false);
    let wire = reference.frame(PAYLOAD);
    for limit in [1, 18, wire.len() - 1] {
        let (io, state) = Controlled::new(wire.clone(), 1, false);
        state.lock().unwrap().read_limit = limit;
        let mut reader = Reader::new(io, receive_codec(3, 29));
        let mut pending = Box::pin(reader.packet());
        assert!(std::future::Future::poll(pending.as_mut(), &mut context()).is_pending());
        drop(pending);
        state.lock().unwrap().read_limit = usize::MAX;
        assert_eq!(reader.packet().await.unwrap().unwrap(), PAYLOAD);
    }
    for options in [0, 13, 16, 29] {
        let (io, state) = Controlled::new(Vec::new(), 1, true);
        let mut writer = Writer::new(io, send_codec(4, options));
        let mut pending = Box::pin(writer.packet(PAYLOAD));
        assert!(std::future::Future::poll(pending.as_mut(), &mut context()).is_pending());
        drop(pending);
        assert_eq!(writer.codec.counter, 1);
        let encoded = writer.output.clone();
        writer.flush().await.unwrap();
        assert_eq!(writer.codec.counter, 1);
        assert_eq!(state.lock().unwrap().output, encoded);
        writer.packet(b"next").await.unwrap();
        let output = state.lock().unwrap().output.clone();
        let mut reference = Reference::new(4, options, true);
        let (first, count) = reference.decode(&output);
        assert_eq!(first, PAYLOAD);
        assert_eq!(reference.decode(&output[count..]).0, b"next");
    }
}

#[tokio::test]
async fn tcp_stream_splits_only_writes_but_read_preserves_all_bytes() {
    let payload: Vec<u8> = (0..200_000).map(|n| n as u8).collect();
    for security in [3, 4, 5] {
        for options in if security == 5 {
            vec![0, 1]
        } else {
            vec![0, 5, 13, 29]
        } {
            let input = if security == 5 && options == 0 {
                payload.clone()
            } else {
                let mut reference = Reference::new(security, options, false);
                let mut wire = Vec::new();
                for piece in payload.chunks(31000) {
                    wire.extend(reference.frame(piece));
                }
                wire.extend(reference.frame(&[]));
                wire
            };
            let (io, state) = Controlled::new(input, 73, true);
            let mut stream = Stream::new(io, security, options, KEY, IV).unwrap();
            let mut got = Vec::new();
            stream.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, payload);
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let output = state.lock().unwrap().output.clone();
            if security == 5 && options == 0 {
                assert_eq!(output, payload);
            } else {
                let mut reference = Reference::new(security, options, true);
                let mut decoded = Vec::new();
                let mut used = 0;
                while used < output.len() {
                    let (bytes, count) = reference.decode(&output[used..]);
                    assert!(bytes.len() <= TCP_CHUNK);
                    decoded.extend(bytes);
                    used += count;
                }
                assert_eq!(decoded, payload);
            }
        }
    }
}

#[tokio::test]
async fn security_five_raw_binary_chunk_boundaries_and_empty_policy() {
    let (io, state) = Controlled::new(b"\0\xff\x80raw".to_vec(), 1, true);
    let (mut reader, mut writer) = split(io, 5, 0, KEY, IV).unwrap();
    assert_eq!(
        reader.packet().await.unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        writer.packet(b"x").await.unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    let mut output = Vec::new();
    reader.read_to_end(&mut output).await.unwrap();
    assert_eq!(output, b"\0\xff\x80raw");
    writer.write_all(b"\xff\0response").await.unwrap();
    writer.shutdown().await.unwrap();
    assert_eq!(state.lock().unwrap().output, b"\xff\0response");

    let input = hex("00030102030001040000deadbeef");
    let (io, state) = Controlled::new(input, 1, true);
    let (mut reader, mut writer) = split(io, 5, 1, KEY, IV).unwrap();
    assert_eq!(reader.packet().await.unwrap().unwrap(), [1, 2, 3]);
    assert_eq!(reader.packet().await.unwrap().unwrap(), [4]);
    assert!(reader.packet().await.unwrap().is_none());
    assert_eq!(state.lock().unwrap().read, 10);
    assert_eq!(
        writer.packet(&[]).await.unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    writer.packet(&[1, 2, 3]).await.unwrap();
    writer.packet(&[4]).await.unwrap();
    writer.shutdown().await.unwrap();
    assert_eq!(state.lock().unwrap().output, hex("00030102030001040000"));
    // 完整 packetaddr 头即使无业务 payload 也不是“空块”。
    let (io, state) = Controlled::new(Vec::new(), 1, false);
    let mut writer = Writer::new(io, receive_codec(5, 1));
    writer.packet(&[1, 127, 0, 0, 1, 0, 53]).await.unwrap();
    assert_eq!(state.lock().unwrap().output, hex("0007017f0000010035"));
}

#[tokio::test]
async fn security_five_truncated_chunks_error_but_boundary_eof_is_legal() {
    let wire = hex("0003010203");
    for cut in 0..=wire.len() {
        let (io, state) = Controlled::new(wire[..cut].to_vec(), 1, true);
        let mut reader = Reader::new(io, receive_codec(5, 1));
        match cut {
            0 => assert!(reader.packet().await.unwrap().is_none()),
            5 => {
                assert_eq!(reader.packet().await.unwrap().unwrap(), [1, 2, 3]);
                assert!(reader.packet().await.unwrap().is_none());
            }
            _ => {
                assert_eq!(
                    reader.packet().await.unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof
                );
                let consumed = state.lock().unwrap().read;
                assert_eq!(
                    reader.packet().await.unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof
                );
                assert_eq!(state.lock().unwrap().read, consumed);
            }
        }
    }
    let (io, _) = Controlled::new(Vec::new(), 1, true);
    let mut reader = Reader::new(io, receive_codec(5, 0));
    assert_eq!(reader.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn packet_interface_refuses_recovering_partial_stream_chunk() {
    let mut reference = Reference::new(3, 0, false);
    let wire = reference.frame(PAYLOAD);
    let (io, _) = Controlled::new(wire, 1, false);
    let mut reader = Reader::new(io, receive_codec(3, 0));
    let mut byte = [0];
    reader.read_exact(&mut byte).await.unwrap();
    assert_eq!(
        reader.packet().await.unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    let mut rest = vec![0; PAYLOAD.len() - 1];
    reader.read_exact(&mut rest).await.unwrap();
    assert_eq!(rest, PAYLOAD[1..]);
    assert!(reader.packet().await.unwrap().is_none());
}

#[tokio::test]
async fn transport_errors_are_not_eof_and_write_failure_is_permanent() {
    for (security, options) in [(3, 0), (3, 29), (5, 0), (5, 1)] {
        let (mut io, _) = Controlled::new(Vec::new(), 1, true);
        io.read_error = Some(io::ErrorKind::ConnectionReset);
        let mut reader = Reader::new(io, receive_codec(security, options));
        let mut output = [0; 1];
        assert_eq!(
            reader.read(&mut output).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        reader.io.read_error = None;
        assert_eq!(
            reader.read(&mut output).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        for zero in [false, true] {
            let (mut io, state) = Controlled::new(Vec::new(), 1, true);
            if zero {
                io.zero_write = true;
            } else {
                io.write_error = Some(io::ErrorKind::ConnectionReset);
            }
            let mut writer = Writer::new(io, receive_codec(security, options));
            let result = writer.write_all(b"data").await;
            let error = match result {
                Err(error) => error,
                Ok(()) => writer.flush().await.unwrap_err(),
            };
            let expected = if zero {
                io::ErrorKind::WriteZero
            } else {
                io::ErrorKind::ConnectionReset
            };
            assert_eq!(error.kind(), expected);
            writer.io.write_error = None;
            writer.io.zero_write = false;
            let calls = state.lock().unwrap().write_calls;
            assert_eq!(writer.write(b"next").await.unwrap_err().kind(), expected);
            assert_eq!(writer.flush().await.unwrap_err().kind(), expected);
            assert_eq!(writer.shutdown().await.unwrap_err().kind(), expected);
            assert_eq!(state.lock().unwrap().write_calls, calls);
        }
    }
}

#[tokio::test]
async fn shutdown_locks_writes_at_first_pending_and_is_idempotent() {
    for (security, options) in [(3, 13), (4, 29), (5, 0), (5, 1)] {
        let (io, state) = Controlled::new(Vec::new(), 1, true);
        let mut writer = Writer::new(io, send_codec(security, options));
        writer.write_all(PAYLOAD).await.unwrap();
        assert!(
            Pin::new(&mut writer)
                .poll_shutdown(&mut context())
                .is_pending()
        );
        let accepted_counter = writer.codec.counter;
        assert_eq!(
            writer.write(b"forbidden").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            writer.packet(b"forbidden").await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(writer.codec.counter, accepted_counter);
        writer.shutdown().await.unwrap();
        let output = state.lock().unwrap().output.clone();
        writer.shutdown().await.unwrap();
        assert_eq!(state.lock().unwrap().output, output);
        assert_eq!(state.lock().unwrap().shutdowns, 1);
        if options == 0 && security == 5 {
            assert_eq!(output, PAYLOAD);
        } else {
            let mut reference = Reference::new(security, options, true);
            let (payload, count) = reference.decode(&output);
            assert_eq!(payload, PAYLOAD);
            let (terminal, end) = reference.decode(&output[count..]);
            assert!(terminal.is_empty());
            assert_eq!(count + end, output.len());
        }
    }
}

#[tokio::test]
async fn read_not_blocked_by_write_backpressure_and_both_half_closes_work() {
    for security in [3, 4, 5] {
        let options = if security == 5 { 1 } else { 29 };
        let mut reference = Reference::new(security, options, false);
        let mut input = reference.frame(PAYLOAD);
        input.extend(reference.frame(&[]));
        let (io, state) = Controlled::new(input, 1, false);
        state.lock().unwrap().blocked_write = true;
        let mut stream = Stream::new(io, security, options, KEY, IV).unwrap();
        stream.write_all(b"pending response").await.unwrap();
        assert!(
            Pin::new(&mut stream)
                .poll_flush(&mut context())
                .is_pending()
        );
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, PAYLOAD);
        state.lock().unwrap().blocked_write = false;
        stream.write_all(b"after peer EOF").await.unwrap();
        stream.shutdown().await.unwrap();

        // 本地方向 shutdown 完成也不能取消未读取的请求方向。
        let mut reference = Reference::new(security, options, false);
        let input = reference.frame(PAYLOAD);
        let (io, _) = Controlled::new(input, 2, true);
        let mut stream = Stream::new(io, security, options, KEY, IV).unwrap();
        stream.shutdown().await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, PAYLOAD);
    }
}

#[tokio::test]
async fn nonce_limit_receive_accepts_65536th_operation_but_never_wraps() {
    for security in [3, 4] {
        for options in [0, 16] {
            let mut reference = Reference::new(security, options, false);
            reference.counter = u16::MAX - 1;
            let mut wire = reference.frame(b"operation65535");
            wire.extend(reference.frame(b"operation65536"));
            wire.extend(reference.frame(b"would wrap to zero"));
            let (io, state) = Controlled::new(wire, 1, true);
            let mut codec = receive_codec(security, options);
            codec.counter = NONCE_LIMIT - 2;
            let mut reader = Reader::new(io, codec);
            assert_eq!(reader.packet().await.unwrap().unwrap(), b"operation65535");
            assert_eq!(reader.packet().await.unwrap().unwrap(), b"operation65536");
            assert_eq!(reader.codec.counter, NONCE_LIMIT);
            assert_eq!(
                reader.packet().await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            let consumed = state.lock().unwrap().read;
            assert!(reader.packet().await.is_err());
            assert_eq!(state.lock().unwrap().read, consumed);
        }
    }
    assert_eq!(nonce(65535, &IV).unwrap(), reference_nonce(65535, &IV));
    assert!(nonce(65536, &IV).is_err());
}

#[test]
fn full_nonce_space_is_walked_without_reset_or_wrap() {
    // 不只把计数器跳到末尾：完整走过 65536 次成熟 AEAD 认证，并拒绝下一次。
    for security in [3, 4] {
        let mut reference = Reference::new(security, 0, false);
        let mut receiver = receive_codec(security, 0);
        let mut sender = receive_codec(security, 0);
        for counter in 0..NONCE_LIMIT {
            let wire = reference.frame(b"x");
            let (length, padding) = receiver.decode_length(&wire[..2]).unwrap();
            assert_eq!(
                receiver
                    .decode_payload(&wire[2..2 + length], padding)
                    .unwrap(),
                b"x"
            );
            assert_eq!(receiver.counter, counter + 1);
            if counter < NONCE_LIMIT - 1 {
                assert_eq!(sender.encode(b"x", false).unwrap(), wire);
            } else {
                assert_eq!(
                    sender.encode(b"x", false).unwrap_err().kind(),
                    io::ErrorKind::InvalidData
                );
                let terminal = sender.encode(&[], true).unwrap();
                let expected = seal(security, &KEY, &IV, u16::MAX, &[]);
                assert_eq!(
                    terminal,
                    [16u16.to_be_bytes().as_slice(), expected.as_slice()].concat()
                );
            }
            assert_eq!(sender.counter, counter + 1);
        }
        assert_eq!(
            receiver
                .decode_length(&18u16.to_be_bytes())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            sender.encode(&[], true).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(sender.counter, NONCE_LIMIT);
        assert_eq!(receiver.counter, NONCE_LIMIT);
    }
}

#[test]
fn wire_allocations_are_bounded_by_one_maximum_frame() {
    for security in [3, 4, 5] {
        for options in if security == 5 {
            vec![1]
        } else {
            vec![0, 13, 16, 29]
        } {
            let mut codec = receive_codec(security, options);
            let mut sequence = codec.sequence.clone();
            let (padding, _) = codec.layout(&mut sequence);
            let maximum_payload = 65535
                - padding
                - if options & AUTH_LENGTH != 0 {
                    0
                } else {
                    codec.tag_len()
                };
            let wire = codec.encode(&vec![0; maximum_payload], false).unwrap();
            let maximum_wire = if options & AUTH_LENGTH != 0 {
                18 + 65535 + 16
            } else {
                2 + 65535
            };
            assert_eq!(wire.len(), maximum_wire);
            assert_eq!(wire.capacity(), wire.len());
        }
    }
}

#[tokio::test]
async fn writer_reserves_last_nonce_for_authenticated_terminal() {
    for security in [3, 4] {
        for options in [0, 16] {
            let (io, state) = Controlled::new(Vec::new(), 1, true);
            let mut codec = send_codec(security, options);
            codec.counter = NONCE_LIMIT - 2;
            let mut writer = Writer::new(io, codec);
            writer.packet(PAYLOAD).await.unwrap();
            assert_eq!(writer.codec.counter, NONCE_LIMIT - 1);
            assert_eq!(
                writer
                    .write(b"cannot consume terminal nonce")
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(writer.codec.counter, NONCE_LIMIT - 1);
            assert_eq!(
                writer.write(b"still forbidden").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
            writer.shutdown().await.unwrap();
            assert_eq!(writer.codec.counter, NONCE_LIMIT);
            let output = state.lock().unwrap().output.clone();
            let mut reference = Reference::new(security, options, true);
            reference.counter = u16::MAX - 1;
            let (payload, used) = reference.decode(&output);
            assert_eq!(payload, PAYLOAD);
            let (terminal, end) = reference.decode(&output[used..]);
            assert!(terminal.is_empty());
            assert_eq!(used + end, output.len());
            let snapshot = output;
            writer.shutdown().await.unwrap();
            assert_eq!(state.lock().unwrap().output, snapshot);
        }
    }
}
