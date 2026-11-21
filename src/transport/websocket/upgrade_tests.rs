use super::*;

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use tokio::io::ReadBuf;

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const EXPECTED_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

fn config() -> WebSocket {
    WebSocket {
        path: "/ws".to_owned(),
        host: None,
        early_data: None,
    }
}

fn header_config(name: &str, max_bytes: usize) -> WebSocket {
    WebSocket {
        early_data: Some(EarlyData::Header {
            max_bytes,
            header_name: name.to_owned(),
        }),
        ..config()
    }
}

fn path_config(max_bytes: usize) -> WebSocket {
    WebSocket {
        early_data: Some(EarlyData::Path { max_bytes }),
        ..config()
    }
}

// 独立手工 HTTP 夹具，密钥/Accept 使用 RFC6455 金样；不调用生产编码器造请求。
fn request(target: &str, host: &str, extra: &str) -> Vec<u8> {
    format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n{extra}\r\n"
    )
    .into_bytes()
}

fn replace(input: &[u8], old: &str, new: &str) -> Vec<u8> {
    String::from_utf8(input.to_vec())
        .expect("ASCII 夹具")
        .replacen(old, new, 1)
        .into_bytes()
}

// 固定 masked Binary 帧，掩码 01 02 03 04，明文 ABC；本模块只归还原始字节。
const FRAME_ABC: &[u8] = &[0x82, 0x83, 1, 2, 3, 4, 0x40, 0x40, 0x40];

struct MemoryIo {
    input: VecDeque<u8>,
    output: Vec<u8>,
    max_read: usize,
    max_write: usize,
    pending: bool,
    read_gate: bool,
    write_gate: bool,
    flush_gate: bool,
    reads: usize,
    flushes: usize,
    input_empty_is_pending: bool,
    flushed: bool,
    fail_write_after: Option<usize>,
    fail_flush: bool,
}

impl MemoryIo {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input: input.into(),
            output: Vec::new(),
            max_read: usize::MAX,
            max_write: usize::MAX,
            pending: false,
            read_gate: false,
            write_gate: false,
            flush_gate: false,
            reads: 0,
            flushes: 0,
            input_empty_is_pending: false,
            flushed: false,
            fail_write_after: None,
            fail_flush: false,
        }
    }

    fn short(input: Vec<u8>, max_read: usize, max_write: usize) -> Self {
        Self {
            max_read,
            max_write,
            pending: true,
            ..Self::new(input)
        }
    }
}

impl AsyncRead for MemoryIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads += 1;
        if self.pending && !self.read_gate {
            self.read_gate = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.read_gate = false;
        if self.input.is_empty() && self.input_empty_is_pending {
            return Poll::Pending;
        }
        let count = self.input.len().min(self.max_read).min(buffer.remaining());
        for _ in 0..count {
            buffer.put_slice(&[self.input.pop_front().expect("长度已检查")]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemoryIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending && !self.write_gate {
            self.write_gate = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.write_gate = false;
        let remaining = match self.fail_write_after {
            Some(limit) if self.output.len() >= limit => {
                return Poll::Ready(Err(io::Error::other("底层错误不应回传的秘密")));
            }
            Some(limit) => limit - self.output.len(),
            None => usize::MAX,
        };
        let count = bytes.len().min(self.max_write).min(remaining);
        self.output.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes += 1;
        if self.pending && !self.flush_gate {
            self.flush_gate = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.flush_gate = false;
        if self.fail_flush {
            return Poll::Ready(Err(io::Error::other("底层刷新错误秘密")));
        }
        self.flushed = true;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("Upgrade 不负责关闭整个承载")
    }
}

fn response_field<'a>(wire: &'a [u8], name: &str) -> Option<&'a str> {
    std::str::from_utf8(wire)
        .expect("ASCII 响应")
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

async fn accepted(input: Vec<u8>, config: &WebSocket) -> (Accepted, MemoryIo) {
    let mut io = MemoryIo::new(input);
    let result = accept(&mut io, config).await;
    let accepted = match result {
        Ok(accepted) => accepted,
        Err(_) => panic!("合法内存握手被拒绝"),
    };
    assert!(
        io.output
            .starts_with(b"HTTP/1.1 101 Switching Protocols\r\n")
    );
    assert_eq!(
        response_field(&io.output, "sec-websocket-accept"),
        Some(EXPECTED_ACCEPT)
    );
    assert_eq!(response_field(&io.output, "upgrade"), Some("websocket"));
    assert_eq!(response_field(&io.output, "connection"), Some("Upgrade"));
    assert!(io.flushed);
    (accepted, io)
}

async fn rejected(input: Vec<u8>, config: &WebSocket, status: &[u8]) -> MemoryIo {
    let mut io = MemoryIo::new(input);
    let error = match accept(&mut io, config).await {
        Ok(_) => panic!("非法内存握手不应成功"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(io.output.starts_with(status));
    assert!(io.output.len() < 128);
    assert!(io.output.ends_with(b"Content-Length: 0\r\n\r\n"));
    assert!(io.flushed);
    io
}

#[tokio::test]
async fn rfc_accept_and_short_pending_reads_writes_flush() {
    for read in [1, 7, 17, 1_024] {
        for write in [1, 7, 17] {
            let mut io = MemoryIo::short(request("/ws", "example.test", ""), read, write);
            let value = accept(&mut io, &config()).await;
            let value = match value {
                Ok(value) => value,
                Err(_) => panic!("短读写合法握手失败"),
            };
            assert!(value.raw_prefix.is_empty());
            assert!(value.early_data.is_empty());
            assert!(io.flushed && io.flushes >= 2);
            assert_eq!(
                response_field(&io.output, "sec-websocket-accept"),
                Some(EXPECTED_ACCEPT)
            );
            assert_eq!(
                io.output
                    .windows(4)
                    .filter(|bytes| *bytes == b"\r\n\r\n")
                    .count(),
                1
            );
            assert!(io.output.ends_with(b"\r\n\r\n"));
        }
    }
}

#[tokio::test]
async fn every_http_truncation_fails_without_sensitive_reflection() {
    let full = request("/ws", "example.test", "X-Secret: never-print-this\r\n");
    for end in 0..full.len() {
        let io = rejected(full[..end].to_vec(), &config(), b"HTTP/1.1 400 ").await;
        assert!(!String::from_utf8_lossy(&io.output).contains("never-print-this"));
    }
}

#[tokio::test]
async fn merged_frame_and_early_prefix_remain_distinct_and_exactly_once() {
    let mut wire = request("/ws", "example.test", "Sec-WebSocket-Protocol: AQI\r\n");
    wire.extend_from_slice(FRAME_ABC);
    wire.extend_from_slice(FRAME_ABC);
    let (value, mut io) = accepted(wire, &header_config("Sec-WebSocket-Protocol", 16)).await;
    assert_eq!(value.early_data, [1, 2]);
    assert_eq!(value.raw_prefix, FRAME_ABC.repeat(2));
    let mut combined_raw = value.raw_prefix;
    io.read_to_end(&mut combined_raw)
        .await
        .expect("读取剩余原始字节");
    assert_eq!(combined_raw, FRAME_ABC.repeat(2));
    assert_eq!(
        response_field(&io.output, "sec-websocket-protocol"),
        Some("AQI")
    );
}

#[tokio::test]
async fn prefix_ownership_for_every_head_frame_coalescing_boundary() {
    let head = request("/ws", "example.test", "");
    for max_read in 1..=head.len() + FRAME_ABC.len() {
        let mut input = head.clone();
        input.extend_from_slice(FRAME_ABC);
        let mut io = MemoryIo::short(input, max_read, 7);
        let value = match accept(&mut io, &config()).await {
            Ok(value) => value,
            Err(_) => panic!("合并边界合法握手失败"),
        };
        let mut raw = value.raw_prefix;
        io.read_to_end(&mut raw).await.expect("读剩余原始流");
        assert_eq!(raw, FRAME_ABC);
        assert!(value.early_data.is_empty());
    }
}

#[tokio::test]
async fn duplicate_singletons_and_body_headers_are_rejected() {
    for extra in [
        "hOsT: example.test\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "sEc-WeBsOcKeT-vErSiOn: 13\r\n",
        "Upgrade: websocket\r\n",
        "Content-Length: 0\r\n",
        "Content-Length: 1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
        "Content-Length: 0\r\nContent-Length: 0\r\n",
    ] {
        rejected(
            request("/ws", "example.test", extra),
            &config(),
            b"HTTP/1.1 400 ",
        )
        .await;
    }
    for extra in [
        "Sec-WebSocket-Protocol: \r\nSec-WebSocket-Protocol: \r\n",
        "Sec-WebSocket-Protocol: AQ\r\nsec-websocket-protocol: AQ\r\n",
    ] {
        rejected(
            request("/ws", "example.test", extra),
            &header_config("Sec-WebSocket-Protocol", 16),
            b"HTTP/1.1 400 ",
        )
        .await;
    }
    rejected(
        request("/ws", "example.test", "X-Ed: AQ\r\nx-ed: AQ\r\n"),
        &header_config("X-Ed", 16),
        b"HTTP/1.1 400 ",
    )
    .await;
}

#[tokio::test]
async fn connection_tokens_merge_but_other_key_fields_do_not() {
    let base = request("/ws", "example.test", "Connection: keep-alive\r\n");
    let wire = replace(&base, "Connection: Upgrade", "cOnNeCtIoN: \tupGRADE\t");
    let wire = replace(&wire, "Upgrade: websocket", "uPgRaDe: WebSocket");
    accepted(wire, &config()).await;
    for value in [
        "close",
        "x-upgrade",
        "Upgrade,",
        ",Upgrade",
        "Upgrade,,close",
        "Upgrade keep-alive",
    ] {
        let wire = replace(
            &request("/ws", "example.test", ""),
            "Connection: Upgrade",
            &format!("Connection: {value}"),
        );
        rejected(wire, &config(), b"HTTP/1.1 400 ").await;
    }
    for (field, value) in [
        ("Upgrade", "websocket, websocket"),
        ("Upgrade", "h2c"),
        ("Sec-WebSocket-Version", "13, 13"),
        ("Sec-WebSocket-Version", "12"),
        ("Sec-WebSocket-Version", "013"),
        ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==,x"),
    ] {
        let old = match field {
            "Upgrade" => "Upgrade: websocket".to_owned(),
            "Sec-WebSocket-Version" => "Sec-WebSocket-Version: 13".to_owned(),
            _ => format!("Sec-WebSocket-Key: {KEY}"),
        };
        let wire = replace(
            &request("/ws", "example.test", ""),
            &old,
            &format!("{field}: {value}"),
        );
        rejected(wire, &config(), b"HTTP/1.1 400 ").await;
    }
}

#[tokio::test]
async fn missing_fields_noncanonical_keys_and_non_http11_get_fail() {
    let base = request("/ws", "example.test", "");
    for removed in [
        "Host: example.test\r\n".to_owned(),
        "Upgrade: websocket\r\n".to_owned(),
        "Connection: Upgrade\r\n".to_owned(),
        "Sec-WebSocket-Version: 13\r\n".to_owned(),
        format!("Sec-WebSocket-Key: {KEY}\r\n"),
    ] {
        rejected(replace(&base, &removed, ""), &config(), b"HTTP/1.1 400 ").await;
    }
    for key in [
        "",
        "AA==",
        "dGhlIHNhbXBsZSBub25jZQ",
        "dGhlIHNhbXBsZSBub25jZR==",
        "______________________==",
        "AAAAAAAAAAAAAAAAAAAAAAA=",
    ] {
        let wire = replace(&base, KEY, key);
        rejected(wire, &config(), b"HTTP/1.1 400 ").await;
    }
    for (old, new) in [
        ("GET ", "POST "),
        ("GET ", "get "),
        ("GET /ws", "GET  /ws"),
        ("HTTP/1.1", "HTTP/1.0"),
        ("HTTP/1.1", "HTTP/2.0"),
        ("HTTP/1.1", "HTTP/1.01"),
        ("HTTP/1.1", "HTTP/1.1 "),
        ("HTTP/1.1", "HTTP/1.1\t"),
    ] {
        rejected(replace(&base, old, new), &config(), b"HTTP/1.1 400 ").await;
    }
}

#[tokio::test]
async fn strict_crlf_obsfold_and_invalid_field_syntax() {
    let base = request("/ws", "example.test", "");
    for wire in [
        replace(&base, "\r\n", "\n"),
        replace(&base, "\r\n", "\rX"),
        replace(&base, "Host:", " Host:"),
        replace(&base, "Host:", "Host :"),
        replace(&base, "Host:", "Ho\0st:"),
        request("/ws", "example.test", "X-Test: one\r\n two\r\n"),
        request("/ws", "example.test", "X-Test: one\r\n\ttwo\r\n"),
        request("/ws", "example.test", "X-Test: one\0two\r\n"),
        request("/ws", "example.test", "X-Test: one\rtwo\r\n"),
        [b"\r\n".as_slice(), base.as_slice()].concat(),
    ] {
        rejected(wire, &config(), b"HTTP/1.1 400 ").await;
    }
    rejected(
        String::from_utf8(base)
            .expect("ASCII")
            .replace("\r\n", "\n")
            .into_bytes(),
        &config(),
        b"HTTP/1.1 400 ",
    )
    .await;
}

fn padded_head(length: usize) -> Vec<u8> {
    let base = request("/ws", "example.test", "X-Pad: \r\n");
    assert!(length >= base.len());
    replace(
        &base,
        "X-Pad: ",
        &format!("X-Pad: {}", "a".repeat(length - base.len())),
    )
}

#[tokio::test]
async fn exact_head_limit_and_no_wait_after_head_or_field_limit() {
    for length in [MAX_HEAD - 1, MAX_HEAD] {
        let (value, _) = accepted(padded_head(length), &config()).await;
        assert!(value.raw_prefix.is_empty());
    }
    rejected(padded_head(MAX_HEAD + 1), &config(), b"HTTP/1.1 431 ").await;
    let full = padded_head(MAX_HEAD + 100);
    let mut io = MemoryIo::new(full[..MAX_HEAD].to_vec());
    io.input_empty_is_pending = true;
    let result = tokio::time::timeout(Duration::from_millis(100), accept(&mut io, &config())).await;
    assert!(matches!(result, Ok(Err(_))));
    assert!(io.output.starts_with(b"HTTP/1.1 431 "));
    assert_eq!(io.reads, MAX_HEAD / READ_CHUNK);

    // 5 个必填头 + 59 个普通头恰好 64；第 65 个只有首字节也须立即拒绝。
    let extras = "X-A: a\r\n".repeat(MAX_HEADERS - 5);
    accepted(request("/ws", "example.test", &extras), &config()).await;
    let mut excess = request("/ws", "example.test", &extras);
    excess.truncate(excess.len() - 2);
    excess.push(b'X');
    let mut io = MemoryIo::new(excess);
    io.input_empty_is_pending = true;
    let result = tokio::time::timeout(Duration::from_millis(100), accept(&mut io, &config())).await;
    assert!(matches!(result, Ok(Err(_))));
    assert!(io.output.starts_with(b"HTTP/1.1 431 "));
}

#[tokio::test]
async fn target_limit_applies_before_waiting_for_request_line_end() {
    let at_limit = format!("/ws?{}", "q".repeat(MAX_TARGET - 4));
    accepted(request(&at_limit, "example.test", ""), &config()).await;
    let over_limit = format!("/ws?{}", "q".repeat(MAX_TARGET - 3));
    rejected(
        request(&over_limit, "example.test", ""),
        &config(),
        b"HTTP/1.1 431 ",
    )
    .await;
    let mut io = MemoryIo::new(format!("GET {over_limit}").into_bytes());
    io.input_empty_is_pending = true;
    let result = tokio::time::timeout(Duration::from_millis(100), accept(&mut io, &config())).await;
    assert!(matches!(result, Ok(Err(_))));
    assert!(io.output.starts_with(b"HTTP/1.1 431 "));
}

#[tokio::test]
async fn finite_preread_and_no_http_body_read() {
    let head = request("/ws", "example.test", "");
    let mut wire = head.clone();
    wire.extend_from_slice(&vec![0x55; MAX_PRE_READ * 2]);
    let (value, io) = accepted(wire, &config()).await;
    assert!(value.raw_prefix.len() <= MAX_RAW_PREFIX);
    assert!(head.len() + value.raw_prefix.len() <= MAX_PRE_READ);
    assert_eq!(value.raw_prefix.len() + io.input.len(), MAX_PRE_READ * 2);
    assert_eq!(io.reads, 1);

    let head = request("/ws", "example.test", "Content-Length: 9000\r\n");
    let mut io = MemoryIo::short(head.clone(), 1, 7);
    io.input_empty_is_pending = true;
    let result = tokio::time::timeout(Duration::from_millis(100), accept(&mut io, &config())).await;
    assert!(matches!(result, Ok(Err(_))));
    assert_eq!(io.reads, head.len() * 2);
    assert!(io.output.starts_with(b"HTTP/1.1 400 "));
}

#[tokio::test]
async fn origin_form_and_path_validation() {
    for target in [
        "http://example.test/ws",
        "https://user@example.test/ws",
        "example.test:443",
        "*",
        "/ws#fragment",
        "/ws%",
        "/ws%0",
        "/ws%GG",
        "/ws%00",
        "/ws%0a",
        "/ws%20",
        "/ws%7f",
        "/ws%80",
        "/ws%3Fsecret",
        "/ws%23secret",
        "/ws\\x",
        "/ws[bad]",
        "/ws?ed=%",
        "/ws?ed=%GG",
        "/ws?ed=1#secret",
        "/ws?ed=\u{80}",
        "/ws\tbad",
        "/ws bad",
    ] {
        rejected(
            request(target, "example.test", ""),
            &config(),
            b"HTTP/1.1 400 ",
        )
        .await;
    }
}

#[tokio::test]
async fn normal_paths_decode_once_exactly_and_query_ed_is_not_a_prefix() {
    for path in ["/ws", "/%77s", "/w%73"] {
        let (value, _) = accepted(request(path, "example.test", ""), &config()).await;
        assert!(value.early_data.is_empty());
    }
    for target in ["/ws?ed=8192", "/ws?ed=AQI", "/ws?ed=1&other=%41", "/ws?"] {
        let (value, _) = accepted(request(target, "example.test", ""), &config()).await;
        assert!(value.early_data.is_empty());
    }
    for target in ["/WS", "/ws/", "/x/../ws", "//ws", "/%2577s", "/wsAQI"] {
        rejected(
            request(target, "example.test", ""),
            &config(),
            b"HTTP/1.1 404 ",
        )
        .await;
    }
    for (configured, target) in [
        ("/%77s", "/ws"),
        ("/a%2Fb", "/a/b"),
        ("/a+b", "/a%2Bb"),
        ("/a%252Fb", "/a%252Fb"),
    ] {
        let cfg = WebSocket {
            path: configured.to_owned(),
            ..config()
        };
        accepted(request(target, "example.test", ""), &cfg).await;
    }
    let cfg = WebSocket {
        path: "/a%252Fb".to_owned(),
        ..config()
    };
    rejected(request("/a/b", "example.test", ""), &cfg, b"HTTP/1.1 404 ").await;
    let cfg = WebSocket {
        path: "/a+b".to_owned(),
        ..config()
    };
    rejected(
        request("/a%20b", "example.test", ""),
        &cfg,
        b"HTTP/1.1 400 ",
    )
    .await;
}

#[tokio::test]
async fn host_authority_validation_even_when_matching_is_disabled() {
    for host in [
        "",
        "user@example.test",
        "user:pass@example.test",
        ":80",
        "example.test:",
        "example.test:no",
        "example.test:+80",
        "example.test:-1",
        "example.test:65536",
        "example.test:80:81",
        "example.test/path",
        "example.test?query",
        "example.test#frag",
        "example.test bad",
        "example.test,other.test",
        "example.test\tbad",
        "exa%mple.test",
        "[not-an-ip]",
        "[v1.test]",
        "[::1",
        "::1",
        "[::1]junk",
        "[::1]:",
        "[::1]:invalid",
        "[::1]:65536",
        "[fe80::1%25zone]",
        "ex\u{e4}mple.test",
    ] {
        rejected(request("/ws", host, ""), &config(), b"HTTP/1.1 400 ").await;
    }
    for host in [
        "example.test",
        "example.test:0",
        "example.test:65535",
        "EXAMPLE.TEST.",
        "127.0.0.1",
        "[::1]",
        "[2001:db8::1]:443",
    ] {
        accepted(request("/ws", host, ""), &config()).await;
    }
}

#[tokio::test]
async fn optional_host_comparison_preserves_trailing_dot_and_port_policy() {
    for (expected, actual) in [
        ("EXAMPLE.TEST", "example.test"),
        ("example.test", "EXAMPLE.TEST:8443"),
        ("example.test:443", "EXAMPLE.TEST:443"),
        ("example.test:443", "example.test:00443"),
        ("[2001:db8::1]", "[2001:0db8:0:0:0:0:0:1]:1234"),
        ("[::1]:443", "[0:0:0:0:0:0:0:1]:443"),
    ] {
        let cfg = WebSocket {
            host: Some(expected.to_owned()),
            ..config()
        };
        accepted(request("/ws", actual, ""), &cfg).await;
    }
    for (expected, actual) in [
        ("example.test", "other.test"),
        ("example.test", "example.test."),
        ("example.test.", "example.test"),
        ("example.test:443", "example.test"),
        ("example.test:443", "example.test:80"),
        ("[::1]", "[::2]"),
        ("[::1]:443", "[::1]"),
        ("127.0.0.1", "[::ffff:127.0.0.1]"),
    ] {
        let cfg = WebSocket {
            host: Some(expected.to_owned()),
            ..config()
        };
        rejected(request("/ws", actual, ""), &cfg, b"HTTP/1.1 404 ").await;
    }
}

#[tokio::test]
async fn origin_extensions_and_forwarded_do_not_change_handshake_policy() {
    let (value, io) = accepted(
        request("/ws", "example.test", "Origin: https://unrelated.test\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\nForwarded: proto=https;host=other.test\r\nX-Forwarded-Proto: https\r\n"),
        &config(),
    ).await;
    assert!(value.early_data.is_empty());
    assert!(response_field(&io.output, "sec-websocket-extensions").is_none());
    assert!(response_field(&io.output, "origin").is_none());
    let cfg = WebSocket {
        host: Some("expected.test".to_owned()),
        ..config()
    };
    rejected(
        request(
            "/ws",
            "wrong.test",
            "Forwarded: host=expected.test;proto=https\r\nX-Forwarded-Host: expected.test\r\n",
        ),
        &cfg,
        b"HTTP/1.1 404 ",
    )
    .await;
}

#[tokio::test]
async fn early_data_defaults_to_off_and_other_sources_are_not_guessed() {
    rejected(
        request("/ws", "example.test", "Sec-WebSocket-Protocol: AQI\r\n"),
        &config(),
        b"HTTP/1.1 400 ",
    )
    .await;
    let (value, io) = accepted(
        request(
            "/ws",
            "example.test",
            "Sec-WebSocket-Protocol: \r\nX-Ed: AQI\r\n",
        ),
        &config(),
    )
    .await;
    assert!(value.early_data.is_empty());
    assert!(response_field(&io.output, "sec-websocket-protocol").is_none());
    for cfg in [header_config("X-Ed", 16), path_config(16)] {
        rejected(
            request("/ws", "example.test", "Sec-WebSocket-Protocol: AQI\r\n"),
            &cfg,
            b"HTTP/1.1 400 ",
        )
        .await;
    }
    let (value, _) = accepted(
        request("/ws?ed=AQI", "example.test", "X-Ed: AQI\r\n"),
        &header_config("Sec-WebSocket-Protocol", 16),
    )
    .await;
    assert!(value.early_data.is_empty());
}

#[tokio::test]
async fn explicit_header_empty_custom_and_protocol_echo_rules() {
    for name in ["Sec-WebSocket-Protocol", "sEc-WeBsOcKeT-pRoToCoL", "X-Ed"] {
        let cfg = header_config(name, 16);
        for extra in ["".to_owned(), format!("{name}: \r\n")] {
            let (value, io) = accepted(request("/ws", "example.test", &extra), &cfg).await;
            assert!(value.early_data.is_empty());
            assert!(response_field(&io.output, "sec-websocket-protocol").is_none());
        }
        let (value, io) = accepted(
            request("/%77s?ed=0", "example.test", &format!("{name}: AQI\r\n")),
            &cfg,
        )
        .await;
        assert_eq!(value.early_data, [1, 2]);
        assert!(response_field(&io.output, "X-Ed").is_none());
        let expected = if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            Some("AQI")
        } else {
            None
        };
        assert_eq!(
            response_field(&io.output, "sec-websocket-protocol"),
            expected
        );
    }
}

#[tokio::test]
async fn raw_url_canonical_encoding_and_prior_limits() {
    for (encoded, decoded) in [
        ("", b"".as_slice()),
        ("AA", &[0]),
        ("AQI", &[1, 2]),
        ("AQID", &[1, 2, 3]),
        ("-_8", &[0xfb, 0xff]),
    ] {
        let cfg = header_config("X-Ed", 16);
        let (value, _) = accepted(
            request("/ws", "example.test", &format!("X-Ed: {encoded}\r\n")),
            &cfg,
        )
        .await;
        assert_eq!(value.early_data, decoded);
    }
    for encoded in [
        "A",
        "AB",
        "AAB",
        "AQJ",
        "AA=",
        "AA==",
        "+/8",
        "/w",
        "a,b",
        "AQI,AQI",
        "AQ I",
        "AQ\tI",
        "AQI;",
        "%41%51",
        "AQI\u{80}",
    ] {
        rejected(
            request("/ws", "example.test", &format!("X-Ed: {encoded}\r\n")),
            &header_config("X-Ed", 16),
            b"HTTP/1.1 400 ",
        )
        .await;
    }
    // max=1 的 ceil(4/3)=2，max=2 的编码上界为3；等长非规范尾位也拒绝。
    for (max, encoded) in [(1, "AQI"), (1, "AB"), (2, "AQID"), (2, "AQJ")] {
        rejected(
            request("/ws", "example.test", &format!("X-Ed: {encoded}\r\n")),
            &header_config("X-Ed", max),
            b"HTTP/1.1 400 ",
        )
        .await;
    }
}

#[tokio::test]
async fn path_mode_uses_exact_raw_base_suffix_and_no_query() {
    for (target, expected) in [
        ("/ws", b"".as_slice()),
        ("/wsAQI", &[1, 2]),
        ("/ws-_8", &[0xfb, 0xff]),
    ] {
        let (value, io) = accepted(
            request(target, "example.test", "X-Ed: AQID\r\n"),
            &path_config(16),
        )
        .await;
        assert_eq!(value.early_data, expected);
        assert!(response_field(&io.output, "sec-websocket-protocol").is_none());
    }
    for target in [
        "/ws?ed=1", "/wsAQI?", "/ws?AQI", "/ws%41QI", "/wsAQI=", "/ws+/8", "/ws/AA", "/wsA",
        "/wsAB",
    ] {
        rejected(
            request(target, "example.test", ""),
            &path_config(16),
            b"HTTP/1.1 400 ",
        )
        .await;
    }
    for target in ["/%77sAQI", "/WSAQI", "/otherAQI"] {
        rejected(
            request(target, "example.test", ""),
            &path_config(16),
            b"HTTP/1.1 404 ",
        )
        .await;
    }
}

#[tokio::test]
async fn maximum_8192_early_data_in_both_modes_and_one_byte_over() {
    let bytes = vec![0xff; MAX_EARLY_DATA];
    // 8192字节全ff，RawURL为10922个'_'和一个'8'，金样不使用生产encoder。
    let encoded = format!("{}8", "_".repeat(10_922));
    for cfg in [
        header_config("Sec-WebSocket-Protocol", MAX_EARLY_DATA),
        path_config(MAX_EARLY_DATA),
    ] {
        let wire = match &cfg.early_data {
            Some(EarlyData::Header { .. }) => request(
                "/ws",
                "example.test",
                &format!("Sec-WebSocket-Protocol: {encoded}\r\n"),
            ),
            _ => request(&format!("/ws{encoded}"), "example.test", ""),
        };
        let (value, _) = accepted(wire, &cfg).await;
        assert_eq!(value.early_data, bytes);
        let too_long = "_".repeat(10_924);
        let wire = match &cfg.early_data {
            Some(EarlyData::Header { .. }) => request(
                "/ws",
                "example.test",
                &format!("Sec-WebSocket-Protocol: {too_long}\r\n"),
            ),
            _ => request(&format!("/ws{too_long}"), "example.test", ""),
        };
        rejected(wire, &cfg, b"HTTP/1.1 400 ").await;
    }
    // 最大1024字节base path + 最大early-data后缀仍处于target限额内。
    let cfg = WebSocket {
        path: format!("/{}", "p".repeat(MAX_PATH - 1)),
        ..path_config(MAX_EARLY_DATA)
    };
    let (value, _) = accepted(
        request(&format!("{}{encoded}", cfg.path), "example.test", ""),
        &cfg,
    )
    .await;
    assert_eq!(value.early_data, bytes);
}

#[tokio::test]
async fn invalid_config_is_rejected_before_reading_or_reflecting() {
    let mut configs = Vec::new();
    for path in [
        "", "ws", "/ws?ed=1", "/ws#x", "/ws%", "/ws%00", "/ws%3f", "/ws bad",
    ] {
        configs.push(WebSocket {
            path: path.to_owned(),
            ..config()
        });
    }
    configs.push(WebSocket {
        path: format!("/{}", "a".repeat(MAX_PATH)),
        ..config()
    });
    configs.push(WebSocket {
        path: "/%77s".to_owned(),
        ..path_config(1)
    });
    for host in ["", "user@host", "host:", "host:65536", "[invalid]"] {
        configs.push(WebSocket {
            host: Some(host.to_owned()),
            ..config()
        });
    }
    for name in [
        "",
        "bad name",
        "bad:name",
        "Host",
        "cOnNeCtIoN",
        "Upgrade",
        "Sec-WebSocket-Key",
        "Sec-WebSocket-Version",
        "Sec-WebSocket-Accept",
        "Sec-WebSocket-Extensions",
        "Content-Length",
        "Transfer-Encoding",
        "Authorization",
        "Cookie",
        "Forwarded",
        "X-Forwarded-For",
        "X-Forwarded-Proto",
        "Proxy-Authorization",
        "Proxy-Authenticate",
        "X-Real-IP",
    ] {
        configs.push(header_config(name, 1));
    }
    configs.push(header_config(&"a".repeat(65), 1));
    for max in [0, MAX_EARLY_DATA + 1, usize::MAX] {
        configs.push(header_config("X-Ed", max));
        configs.push(path_config(max));
    }
    for cfg in configs {
        let mut io = MemoryIo::new(request("/ws", "example.test", ""));
        let error = match accept(&mut io, &cfg).await {
            Ok(_) => panic!("非法配置应在读取前失败"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(io.reads, 0);
        assert!(io.output.is_empty());
    }
    accepted(
        request(
            "/ws",
            "example.test",
            &format!("{}: AQ\r\n", "a".repeat(64)),
        ),
        &header_config(&"a".repeat(64), 1),
    )
    .await;
}

#[tokio::test]
async fn fixed_errors_do_not_reflect_uri_headers_or_decoded_secrets() {
    let secret = "c2VjcmV0LXByZWZpeA";
    for (wire, cfg, status) in [
        (
            request(&format!("/other?secret={secret}"), "example.test", ""),
            config(),
            b"HTTP/1.1 404 ".as_slice(),
        ),
        (
            request("/ws", &format!("{secret}:no"), ""),
            config(),
            b"HTTP/1.1 400 ".as_slice(),
        ),
        (
            request(
                "/ws",
                "example.test",
                &format!("Sec-WebSocket-Protocol: {secret}=\r\n"),
            ),
            header_config("Sec-WebSocket-Protocol", 64),
            b"HTTP/1.1 400 ".as_slice(),
        ),
        (
            request(&format!("/ws{secret}?ed=1"), "example.test", ""),
            path_config(64),
            b"HTTP/1.1 400 ".as_slice(),
        ),
    ] {
        let mut io = MemoryIo::new(wire);
        let error = match accept(&mut io, &cfg).await {
            Ok(_) => panic!("秘密负向夹具应失败"),
            Err(error) => error,
        };
        assert!(io.output.starts_with(status));
        let rendered = format!("{error} {error:?} {}", String::from_utf8_lossy(&io.output));
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("secret-prefix"));
        assert!(!rendered.contains("Sec-WebSocket-Protocol"));
    }
}

struct Counter(AtomicUsize);

impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn flush_must_finish_and_partial_101_errors_never_append_an_http_error() {
    let mut io = MemoryIo::new(request("/ws", "example.test", ""));
    io.fail_flush = true;
    let error = match accept(&mut io, &config()).await {
        Ok(_) => panic!("刷新错误不能返回 Accepted"),
        Err(error) => error,
    };
    assert!(!error.to_string().contains("秘密"));
    assert!(io.output.starts_with(b"HTTP/1.1 101 "));
    assert!(!io.output.windows(4).any(|bytes| bytes == b"400 "));

    let mut io = MemoryIo::new(request("/ws", "example.test", ""));
    io.fail_write_after = Some(17);
    let error = match accept(&mut io, &config()).await {
        Ok(_) => panic!("部分101写出后失败不能返回 Accepted"),
        Err(error) => error,
    };
    assert_eq!(io.output.len(), 17);
    assert_eq!(io.flushes, 0);
    assert!(!format!("{error:?}").contains("秘密"));

    let mut io = MemoryIo::new(request("/ws", "example.test", ""));
    io.pending = true;
    io.read_gate = true;
    io.write_gate = true;
    let cfg = config();
    let wake = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    {
        let mut future = Box::pin(accept(&mut io, &cfg));
        assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
        assert!(wake.0.load(Ordering::Relaxed) > 0);
        // 第一次 poll 已写101，但 flush 为 Pending；丢弃未来不产生后台writer。
    }
    assert!(io.output.starts_with(b"HTTP/1.1 101 "));
    assert!(!io.flushed);
    assert_eq!(io.flushes, 1);
}

#[tokio::test]
async fn duplex_fragmented_handshake_returns_unparsed_tail() {
    let (mut server, mut client) = tokio::io::duplex(32);
    let wire = request("/ws", "example.test", "X-Ed: AQI\r\n");
    let cfg = header_config("X-Ed", 16);
    let server_side = async {
        let value = match accept(&mut server, &cfg).await {
            Ok(value) => value,
            Err(_) => panic!("duplex 合法握手失败"),
        };
        let mut raw = value.raw_prefix;
        let missing = FRAME_ABC.len() - raw.len();
        let mut rest = vec![0; missing];
        server.read_exact(&mut rest).await.expect("剩余帧字节");
        raw.extend_from_slice(&rest);
        assert_eq!(raw, FRAME_ABC);
        assert_eq!(value.early_data, [1, 2]);
    };
    let client_side = async {
        for byte in wire {
            client.write_all(&[byte]).await.expect("写头字节");
        }
        client.write_all(FRAME_ABC).await.expect("写原始帧");
        let mut response = Vec::new();
        loop {
            let byte = client.read_u8().await.expect("读101字节");
            response.push(byte);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert_eq!(
            response_field(&response, "sec-websocket-accept"),
            Some(EXPECTED_ACCEPT)
        );
        assert!(response_field(&response, "sec-websocket-protocol").is_none());
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(server_side, client_side)
    })
    .await
    .expect("duplex 不应死锁");
}

#[tokio::test(start_paused = true)]
async fn parent_absolute_timeout_includes_slow_read_and_blocked_101_without_restart() {
    let (mut server, mut client) = tokio::io::duplex(16);
    let cfg = config();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let accept_side = tokio::time::timeout_at(deadline, accept(&mut server, &cfg));
    let slow_side = async {
        tokio::time::sleep(Duration::from_secs(8)).await;
        client
            .write_all(&request("/ws", "example.test", ""))
            .await
            .expect("慢头写入");
        // 不读101：其余2秒必须包含响应背压，不能重新得到完整期限。
        tokio::time::sleep(Duration::from_secs(3)).await;
    };
    let (result, ()) = tokio::join!(accept_side, slow_side);
    assert!(result.is_err());
    assert_eq!(
        tokio::time::Instant::now(),
        deadline + Duration::from_secs(1)
    );
}
