use super::*;
use std::{
    collections::VecDeque,
    future::Future,
    io::{Cursor, IoSlice},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Wake, Waker},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn counting_waker() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount::default());
    (count.clone(), Waker::from(count))
}

#[derive(Clone, Copy)]
enum ReadStep {
    Bytes(usize),
    Pending,
    Error(io::ErrorKind),
}

/// 独立内存 IO：可控制每次短读、Pending、错误及所有写方向操作。
struct Wire {
    input: Vec<u8>,
    offset: usize,
    chunk: usize,
    alternate: bool,
    read_pending: bool,
    write_pending: bool,
    flush_pending: bool,
    shutdown_pending: bool,
    steps: VecDeque<ReadStep>,
    reads: usize,
    writes: usize,
    vectored_writes: usize,
    flushes: usize,
    shutdowns: usize,
    output: Vec<u8>,
    write_error: Option<io::ErrorKind>,
    flush_error: Option<io::ErrorKind>,
    shutdown_error: Option<io::ErrorKind>,
}

impl Wire {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            offset: 0,
            chunk: usize::MAX,
            alternate: false,
            read_pending: false,
            write_pending: false,
            flush_pending: false,
            shutdown_pending: false,
            steps: VecDeque::new(),
            reads: 0,
            writes: 0,
            vectored_writes: 0,
            flushes: 0,
            shutdowns: 0,
            output: Vec::new(),
            write_error: None,
            flush_error: None,
            shutdown_error: None,
        }
    }

    fn pend(alternate: bool, pending: &mut bool, cx: &Context<'_>) -> bool {
        if !alternate {
            return false;
        }
        *pending = !*pending;
        if *pending {
            cx.waker().wake_by_ref();
        }
        *pending
    }
}

impl AsyncRead for Wire {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.reads += 1;
        let limit = match this.steps.pop_front() {
            Some(ReadStep::Pending) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Some(ReadStep::Error(kind)) => {
                return Poll::Ready(Err(io::Error::new(kind, "受控读取失败")));
            }
            Some(ReadStep::Bytes(n)) => n,
            None => {
                if Self::pend(this.alternate, &mut this.read_pending, cx) {
                    return Poll::Pending;
                }
                this.chunk
            }
        };
        let n = limit
            .min(out.remaining())
            .min(this.input.len() - this.offset);
        out.put_slice(&this.input[this.offset..this.offset + n]);
        this.offset += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.writes += 1;
        if Self::pend(this.alternate, &mut this.write_pending, cx) {
            return Poll::Pending;
        }
        if let Some(kind) = this.write_error {
            return Poll::Ready(Err(io::Error::new(kind, "受控写入失败")));
        }
        let n = this.chunk.min(bytes.len());
        this.output.extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.flushes += 1;
        if Self::pend(this.alternate, &mut this.flush_pending, cx) {
            return Poll::Pending;
        }
        Poll::Ready(match this.flush_error {
            Some(kind) => Err(io::Error::new(kind, "受控 flush 失败")),
            None => Ok(()),
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.shutdowns += 1;
        if Self::pend(this.alternate, &mut this.shutdown_pending, cx) {
            return Poll::Pending;
        }
        Poll::Ready(match this.shutdown_error {
            Some(kind) => Err(io::Error::new(kind, "受控 shutdown 失败")),
            None => Ok(()),
        })
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.vectored_writes += 1;
        if Self::pend(this.alternate, &mut this.write_pending, cx) {
            return Poll::Pending;
        }
        if let Some(kind) = this.write_error {
            return Poll::Ready(Err(io::Error::new(kind, "受控向量写入失败")));
        }
        let mut n = 0;
        for buffer in buffers {
            let take = buffer.len().min(this.chunk - n);
            this.output.extend_from_slice(&buffer[..take]);
            n += take;
            if n == this.chunk {
                break;
            }
        }
        Poll::Ready(Ok(n))
    }
}

#[derive(Debug, PartialEq)]
enum ReadResult {
    Data(Vec<u8>),
    Pending,
    Error(io::ErrorKind),
}

/// 不隐式 begin_poll：可模拟成熟引擎在一次外层 poll 内重复调用底层 read。
fn read_once<S: AsyncRead + Unpin>(
    guard: &mut Guard<S>,
    waker: &Waker,
    capacity: usize,
) -> ReadResult {
    let mut storage = vec![0; capacity];
    let mut out = ReadBuf::new(&mut storage);
    match Pin::new(guard).poll_read(&mut Context::from_waker(waker), &mut out) {
        Poll::Ready(Ok(())) => ReadResult::Data(out.filled().to_vec()),
        Poll::Ready(Err(error)) => {
            assert!(out.filled().is_empty(), "错误不能同时交付部分原始头");
            ReadResult::Error(error.kind())
        }
        Poll::Pending => {
            assert!(out.filled().is_empty(), "Pending 的字节所有权必须仍归护栏");
            ReadResult::Pending
        }
    }
}

/// 每次迭代代表一个新的外层 poll，有明确迭代上限而不靠墙钟超时。
fn collect<S: AsyncRead + Unpin>(
    guard: &mut Guard<S>,
    capacity: usize,
) -> Result<Vec<u8>, io::ErrorKind> {
    let (_, waker) = counting_waker();
    let mut result = Vec::new();
    for _ in 0..100_000 {
        guard.begin_poll();
        match read_once(guard, &waker, capacity) {
            ReadResult::Data(bytes) if bytes.is_empty() => return Ok(result),
            ReadResult::Data(bytes) => result.extend(bytes),
            ReadResult::Pending => {}
            ReadResult::Error(kind) => return Err(kind),
        }
    }
    panic!("受控输入超过确定性的 poll 上限");
}

/// 一个外层 poll 内读到 Pending/EOF，返回是否遇到 EOF；绝不重置预算。
fn collect_round<S: AsyncRead + Unpin>(
    guard: &mut Guard<S>,
    waker: &Waker,
    capacity: usize,
) -> (Vec<u8>, bool) {
    let mut bytes = Vec::new();
    for _ in 0..10_000 {
        match read_once(guard, waker, capacity) {
            ReadResult::Data(part) if part.is_empty() => return (bytes, true),
            ReadResult::Data(part) => bytes.extend(part),
            ReadResult::Pending => return (bytes, false),
            ReadResult::Error(kind) => panic!("受控合法输入失败：{kind:?}"),
        }
    }
    panic!("一次外层 poll 内底层 read 无界重入");
}

// 测试端独立构造线格式，不调用生产解析函数，也不依赖生产限额常量。
const MASK: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
const GOLDEN: [u8; 9] = [0x82, 0x83, 0x12, 0x34, 0x56, 0x78, 0x73, 0x56, 0x35];

fn length_header(first: u8, marker: u8, length: u64) -> Vec<u8> {
    let mut header = vec![first, 0x80 | marker];
    match marker {
        126 => header.extend_from_slice(&(length as u16).to_be_bytes()),
        127 => header.extend_from_slice(&length.to_be_bytes()),
        _ => assert_eq!(u64::from(marker), length),
    }
    header
}

fn frame(first: u8, payload: &[u8]) -> Vec<u8> {
    let marker = match payload.len() {
        0..=125 => payload.len() as u8,
        126..=65_535 => 126,
        _ => 127,
    };
    let mut result = length_header(first, marker, payload.len() as u64);
    result.extend_from_slice(&MASK);
    result.extend(
        payload
            .iter()
            .enumerate()
            .map(|(i, byte)| byte ^ MASK[i % 4]),
    );
    result
}

#[test]
fn io_traits_remain_unpin_and_send() {
    fn assert_io<T: AsyncRead + AsyncWrite + Unpin + Send>() {}
    assert_io::<Guard<Wire>>();
    assert_io::<Guard<tokio::io::DuplexStream>>();
}

#[test]
fn literal_wire_is_unchanged_at_every_prefix_split_and_output_size() {
    assert_eq!(frame(0x82, b"abc"), GOLDEN);
    for split in 0..=GOLDEN.len() {
        for capacity in [1, 2, 3, 7, 17, 128] {
            let mut guard = Guard::new(
                Cursor::new(GOLDEN[split..].to_vec()),
                GOLDEN[..split].to_vec(),
            );
            assert_eq!(collect(&mut guard, capacity).unwrap(), GOLDEN);
            assert!(guard.raw.prefix.is_empty());
        }
    }
}

#[test]
fn prefix_is_drained_before_socket_is_polled() {
    let second = frame(0x89, b"ping");
    let mut guard = Guard::new(Wire::new(second.clone()), GOLDEN.to_vec());
    let (_, waker) = counting_waker();
    let mut prefix = Vec::new();
    while prefix.len() < GOLDEN.len() {
        match read_once(&mut guard, &waker, 1) {
            ReadResult::Data(bytes) => {
                assert_eq!(bytes.len(), 1);
                prefix.extend(bytes);
            }
            other => panic!("完整前缀不应等 socket：{other:?}"),
        }
        assert_eq!(guard.get_mut().reads, 0);
    }
    assert_eq!(prefix, GOLDEN);
    assert!(guard.raw.prefix.is_empty());
    assert_eq!(collect(&mut guard, 17).unwrap(), second);
}

#[test]
fn every_header_truncation_is_unexpected_eof_without_header_leakage() {
    for payload_length in [0, 126, 65_536] {
        let marker = match payload_length {
            0 => 0,
            126 => 126,
            _ => 127,
        };
        let mut header = length_header(0x82, marker, payload_length);
        header.extend_from_slice(&MASK);
        for cut in 1..header.len() {
            for split in 0..=cut {
                for chunk in [1, 7, 17] {
                    let mut io = Wire::new(header[split..cut].to_vec());
                    io.chunk = chunk;
                    let mut guard = Guard::new(io, header[..split].to_vec());
                    let (_, waker) = counting_waker();
                    assert_eq!(
                        read_once(&mut guard, &waker, 128),
                        ReadResult::Error(io::ErrorKind::UnexpectedEof),
                        "头长 {}，截于 {cut}，前缀 {split}，短读 {chunk}",
                        header.len()
                    );
                    let calls = guard.get_mut().reads;
                    guard.begin_poll();
                    assert_eq!(
                        read_once(&mut guard, &waker, 128),
                        ReadResult::Error(io::ErrorKind::UnexpectedEof)
                    );
                    assert_eq!(guard.get_mut().reads, calls);
                }
            }
        }
    }
}

#[test]
fn legal_length_boundaries_pass_verbatim_including_one_mib() {
    for length in [0, 1, 125, 126, 127, 65_535, 65_536, 1_048_576] {
        let payload: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
        let wire = frame(0x82, &payload);
        for split in [0, 1, 2, 5, 6, wire.len()] {
            let split = split.min(wire.len());
            let mut guard = Guard::new(Cursor::new(wire[split..].to_vec()), wire[..split].to_vec());
            assert_eq!(collect(&mut guard, 4096).unwrap(), wire);
        }
    }
}

/// 无 mask key、无 payload 的长度声明也必须立即拒绝，后续合法帧不能重同步。
fn assert_declaration_rejected(header: &[u8]) {
    let (_, waker) = counting_waker();
    for split in 0..=header.len() {
        let mut socket = header[split..].to_vec();
        socket.extend_from_slice(&GOLDEN);
        let mut guard = Guard::new(Wire::new(socket), header[..split].to_vec());
        assert_eq!(
            read_once(&mut guard, &waker, 128),
            ReadResult::Error(io::ErrorKind::InvalidData)
        );
        assert_eq!(guard.get_mut().offset, header.len() - split);
        let reads = guard.get_mut().reads;
        guard.begin_poll();
        assert_eq!(
            read_once(&mut guard, &waker, 128),
            ReadResult::Error(io::ErrorKind::InvalidData)
        );
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            Pin::new(&mut guard).poll_write(&mut cx, b"blocked"),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData
        ));
        assert_eq!(guard.get_mut().reads, reads);
        assert_eq!(guard.get_mut().writes, 0);
    }
}

#[test]
fn nonminimal_126_and_127_encodings_are_rejected_at_length_field() {
    for length in [0, 1, 124, 125] {
        assert_declaration_rejected(&length_header(0x82, 126, length));
    }
    for length in [0, 1, 125, 126, 127, 65_534, 65_535] {
        assert_declaration_rejected(&length_header(0x82, 127, length));
    }
}

#[test]
fn high_bit_and_oversize_declarations_fail_without_payload_or_key() {
    for length in [
        1_048_577,
        u32::MAX as u64,
        1 << 32,
        (1 << 63) - 1,
        1 << 63,
        (1 << 63) | 65_536,
        u64::MAX,
    ] {
        assert_declaration_rejected(&length_header(0x82, 127, length));
    }
}

#[test]
fn invalid_header_only_never_waits_for_a_stalled_socket() {
    let declarations = [
        length_header(0x82, 126, 125),
        length_header(0x82, 127, 65_535),
        length_header(0x82, 127, 1_048_577),
        length_header(0x82, 127, 1 << 63),
        length_header(0x89, 126, 126),
        length_header(0x09, 0, 0),
    ];
    let (_, waker) = counting_waker();
    for declaration in declarations {
        // 若护栏试图等待 mask/payload，下一次 read 会是 Pending，而非预期错误。
        let mut io = Wire::new(declaration.clone());
        io.steps.extend([
            ReadStep::Bytes(2),
            ReadStep::Bytes(declaration.len().saturating_sub(2)),
            ReadStep::Pending,
        ]);
        let mut guard = Guard::new(io, Vec::new());
        assert_eq!(
            read_once(&mut guard, &waker, 128),
            ReadResult::Error(io::ErrorKind::InvalidData)
        );
        assert_eq!(guard.get_mut().offset, declaration.len());
        // 全部由 HTTP 尾部提供时，连一次 socket poll 都不能发生。
        let mut io = Wire::new(Vec::new());
        io.steps.push_back(ReadStep::Pending);
        let mut guard = Guard::new(io, declaration);
        assert_eq!(
            read_once(&mut guard, &waker, 128),
            ReadResult::Error(io::ErrorKind::InvalidData)
        );
        assert_eq!(guard.get_mut().reads, 0);
    }
}

#[test]
fn control_fin_length_boundary_and_client_mask_are_enforced() {
    for opcode in [0x8, 0x9, 0xa] {
        let valid = frame(0x80 | opcode, &[0x55; 125]);
        let mut guard = Guard::new(Cursor::new(valid.clone()), Vec::new());
        assert_eq!(collect(&mut guard, 7).unwrap(), valid);
        assert_declaration_rejected(&length_header(opcode, 0, 0));
        assert_declaration_rejected(&length_header(0x80 | opcode, 126, 126));
        assert_declaration_rejected(&length_header(0x80 | opcode, 127, 65_536));
    }
    assert_declaration_rejected(&[0x82, 0x00]);
    assert_declaration_rejected(&[0x89, 0x01]);
}

#[test]
fn rsv_opcode_text_and_continuation_state_are_left_to_the_engine() {
    let mut wire = Vec::new();
    // 包含尚无起始消息的 continuation、RSV、保留 opcode 和 text；窄护栏
    // 只保留结构边界，不将这些原始输入当成已通过完整 WebSocket 验证。
    for first in [0x00, 0x80, 0xc2, 0xa2, 0x92, 0x83, 0x8b, 0x81] {
        wire.extend(frame(first, b"raw"));
    }
    let mut guard = Guard::new(Cursor::new(wire.clone()), Vec::new());
    assert_eq!(collect(&mut guard, 17).unwrap(), wire);
}

#[test]
fn consecutive_headers_and_payload_that_looks_like_headers_are_not_confused() {
    let mut payload = GOLDEN.to_vec();
    payload.extend_from_slice(&length_header(0x82, 127, u64::MAX));
    let mut wire = frame(0x02, &payload);
    wire.extend(frame(0x89, b"ping"));
    wire.extend(frame(0x80, &[]));
    wire.extend(frame(0x82, b"next"));
    for split in 0..=wire.len() {
        let mut io = Wire::new(wire[split..].to_vec());
        io.chunk = 1;
        let mut guard = Guard::new(io, wire[..split].to_vec());
        assert_eq!(collect(&mut guard, 1).unwrap(), wire);
    }
}

#[test]
fn one_seven_seventeen_byte_short_reads_and_alternating_pending_keep_ownership() {
    let mut wire = frame(0x02, &[0x5a; 126]);
    wire.extend(frame(0x89, b"ping"));
    wire.extend(frame(0x80, b"last"));
    for chunk in [1, 7, 17] {
        for split in [0, 1, 3, 7, 8, wire.len() / 2, wire.len()] {
            let mut io = Wire::new(wire[split..].to_vec());
            io.chunk = chunk;
            io.alternate = true;
            let mut guard = Guard::new(io, wire[..split].to_vec());
            assert_eq!(collect(&mut guard, 7).unwrap(), wire);
        }
    }
}

#[test]
fn cancelling_read_futures_at_every_partial_header_keeps_all_bytes() {
    let wire = frame(0x82, &[0x43; 65_536]);
    for held in 1..14 {
        let mut io = Wire::new(wire.clone());
        let mut remaining = held;
        for target in [2, 10, 14] {
            let n = remaining.min(target - (held - remaining));
            if n != 0 {
                io.steps.push_back(ReadStep::Bytes(n));
                remaining -= n;
            }
            if remaining == 0 {
                break;
            }
        }
        io.steps.push_back(ReadStep::Pending);
        let mut guard = Guard::new(io, Vec::new());
        let (_, waker) = counting_waker();
        let mut storage = [0xa5; 17];
        {
            let mut future = Box::pin(guard.read(&mut storage));
            assert!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
        }
        assert_eq!(storage, [0xa5; 17]);
        assert_eq!(guard.filled, held);
        assert_eq!(guard.get_mut().offset, held);
        assert_eq!(guard.headers_left, 31);
        assert_eq!(guard.bytes_left, 65_536 - held);
        // 换一个 future/输出缓冲再读，已取得的半头不得丢失、重复或重新计费。
        assert_eq!(collect(&mut guard, 4096).unwrap(), wire);
    }
}

#[test]
fn cancelled_header_replay_and_payload_reads_resume_at_exact_cursor() {
    let mut io = Wire::new(GOLDEN.to_vec());
    io.steps
        .extend([ReadStep::Bytes(2), ReadStep::Bytes(4), ReadStep::Pending]);
    let mut guard = Guard::new(io, Vec::new());
    let (_, waker) = counting_waker();
    let mut received = Vec::new();
    for _ in 0..6 {
        match read_once(&mut guard, &waker, 1) {
            ReadResult::Data(bytes) => received.extend(bytes),
            other => panic!("头部回放意外结果：{other:?}"),
        }
    }
    assert_eq!(received, GOLDEN[..6]);
    let mut abandoned = [0xa5; 1];
    {
        let mut future = Box::pin(guard.read(&mut abandoned));
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
    }
    assert_eq!(abandoned, [0xa5]);
    received.extend(collect(&mut guard, 1).unwrap());
    assert_eq!(received, GOLDEN);
}

#[test]
fn payload_truncation_is_a_permanent_error_not_eof() {
    let wire = frame(0x82, b"payload");
    let (_, waker) = counting_waker();
    for cut in 6..wire.len() {
        let mut guard = Guard::new(Wire::new(wire[..cut].to_vec()), Vec::new());
        let mut received = Vec::new();
        for _ in 0..32 {
            match read_once(&mut guard, &waker, 2) {
                ReadResult::Data(bytes) => {
                    assert!(!bytes.is_empty(), "载荷截断不得伪造 EOF");
                    received.extend(bytes);
                }
                ReadResult::Error(kind) => {
                    assert_eq!(kind, io::ErrorKind::UnexpectedEof);
                    break;
                }
                ReadResult::Pending => panic!("内存输入不应 Pending"),
            }
        }
        assert_eq!(received, wire[..cut]);
        let reads = guard.get_mut().reads;
        guard.begin_poll();
        assert_eq!(
            read_once(&mut guard, &waker, 17),
            ReadResult::Error(io::ErrorKind::UnexpectedEof)
        );
        assert_eq!(guard.get_mut().reads, reads);
    }
}

#[test]
fn raw_eof_at_frame_boundary_is_left_to_mature_close_validation() {
    let (_, waker) = counting_waker();
    for wire in [Vec::new(), GOLDEN.to_vec()] {
        let mut guard = Guard::new(Wire::new(wire.clone()), Vec::new());
        assert_eq!(collect(&mut guard, 17).unwrap(), wire);
        let reads = guard.get_mut().reads;
        assert_eq!(
            read_once(&mut guard, &waker, 17),
            ReadResult::Data(Vec::new())
        );
        assert_eq!(guard.get_mut().reads, reads);
    }
}

#[test]
fn empty_frame_flood_is_limited_to_32_new_headers_per_outer_poll() {
    let (_, waker) = counting_waker();
    for first in [0x82, 0x00, 0x89, 0x8a] {
        let empty = frame(first, &[]);
        let wire = empty.repeat(97);
        for split in [0, 1, 191, 193, wire.len()] {
            let mut io = Wire::new(wire[split..].to_vec());
            io.chunk = 1;
            let mut guard = Guard::new(io, wire[..split].to_vec());
            let mut received = Vec::new();
            for _ in 0..3 {
                guard.begin_poll();
                let (round, eof) = collect_round(&mut guard, &waker, 1);
                assert!(!eof);
                assert_eq!(round, empty.repeat(32));
                assert_eq!(guard.headers_left, 0);
                assert_eq!(guard.bytes_left, 65_536 - 32 * 6);
                let reads = guard.get_mut().reads;
                let offset = guard.get_mut().offset;
                for _ in 0..3 {
                    assert_eq!(read_once(&mut guard, &waker, 17), ReadResult::Pending);
                }
                assert_eq!(guard.get_mut().reads, reads);
                assert_eq!(guard.get_mut().offset, offset);
                received.extend(round);
            }
            guard.begin_poll();
            let (last, eof) = collect_round(&mut guard, &waker, 17);
            assert!(eof);
            received.extend(last);
            assert_eq!(received, wire);
        }
    }
}

#[test]
fn budget_pending_wakes_current_waker_and_only_begin_poll_resets_it() {
    let (first_count, first_waker) = counting_waker();
    let (second_count, second_waker) = counting_waker();
    let empty = frame(0x00, &[]);
    let mut guard = Guard::new(Wire::new(empty.repeat(33)), Vec::new());
    let (round, eof) = collect_round(&mut guard, &first_waker, 128);
    assert!(!eof);
    assert_eq!(round, empty.repeat(32));
    assert_eq!(first_count.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        read_once(&mut guard, &second_waker, 17),
        ReadResult::Pending
    );
    assert_eq!(second_count.0.load(Ordering::SeqCst), 1);
    assert_eq!(first_count.0.load(Ordering::SeqCst), 1);
    let reads = guard.get_mut().reads;
    let mut cx = Context::from_waker(&second_waker);
    assert!(matches!(
        Pin::new(&mut guard).poll_write(&mut cx, b"out"),
        Poll::Ready(Ok(3))
    ));
    assert!(matches!(
        Pin::new(&mut guard).poll_flush(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        Pin::new(&mut guard).poll_shutdown(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(
        read_once(&mut guard, &second_waker, 17),
        ReadResult::Pending
    );
    assert_eq!(guard.get_mut().reads, reads);
    guard.begin_poll();
    assert_eq!(
        read_once(&mut guard, &second_waker, 17),
        ReadResult::Data(empty)
    );
}

#[test]
fn a_header_start_is_charged_once_across_pending_and_outer_polls() {
    let mut io = Wire::new(GOLDEN.to_vec());
    io.steps.extend([ReadStep::Bytes(1), ReadStep::Pending]);
    let mut guard = Guard::new(io, Vec::new());
    let (_, waker) = counting_waker();
    assert_eq!(read_once(&mut guard, &waker, 17), ReadResult::Pending);
    assert_eq!(guard.headers_left, 31);
    assert_eq!(guard.bytes_left, 65_535);
    guard.begin_poll();
    assert_eq!(
        read_once(&mut guard, &waker, 1),
        ReadResult::Data(vec![0x82])
    );
    assert_eq!(guard.headers_left, 32, "完成前一轮已开始的头不能算新头");
    assert_eq!(guard.bytes_left, 65_531);
    assert_eq!(guard.get_mut().offset, 6);
}

#[test]
fn raw_byte_budget_counts_prefix_once_and_spans_socket_reentry() {
    let wire = frame(0x82, &[0x5a; 131_072]);
    let (_, waker) = counting_waker();
    for split in [0, 13, 65_536 + 23, wire.len()] {
        let mut guard = Guard::new(Wire::new(wire[split..].to_vec()), wire[..split].to_vec());
        let mut received = Vec::new();
        for round_index in 0..2 {
            guard.begin_poll();
            let (round, eof) = collect_round(&mut guard, &waker, 8192);
            assert!(!eof);
            assert_eq!(round.len(), 65_536);
            assert_eq!(guard.bytes_left, 0);
            if split > 65_536 && round_index == 0 {
                assert_eq!(guard.get_mut().reads, 0);
            }
            let reads = guard.get_mut().reads;
            assert_eq!(read_once(&mut guard, &waker, 17), ReadResult::Pending);
            assert_eq!(guard.get_mut().reads, reads);
            received.extend(round);
        }
        guard.begin_poll();
        let (last, eof) = collect_round(&mut guard, &waker, 8192);
        assert!(eof);
        assert_eq!(last.len(), 14);
        received.extend(last);
        assert_eq!(received, wire);
    }
}

#[test]
fn byte_budget_can_stop_mid_header_without_exposing_or_losing_it() {
    let first = frame(0x82, &[0x44; 65_527]);
    assert_eq!(first.len(), 65_535);
    let mut wire = first.clone();
    wire.extend_from_slice(&GOLDEN);
    let mut guard = Guard::new(Wire::new(Vec::new()), wire.clone());
    let (count, waker) = counting_waker();
    let (round, eof) = collect_round(&mut guard, &waker, 8192);
    assert!(!eof);
    assert_eq!(round, first);
    assert_eq!(guard.filled, 1);
    assert_eq!(guard.bytes_left, 0);
    assert_eq!(guard.headers_left, 30);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert_eq!(guard.get_mut().reads, 0);
    assert_eq!(read_once(&mut guard, &waker, 17), ReadResult::Pending);
    guard.begin_poll();
    let (rest, eof) = collect_round(&mut guard, &waker, 1);
    assert!(eof);
    assert_eq!(rest, GOLDEN);
    assert_eq!(guard.headers_left, 32);
    assert_eq!([round, rest].concat(), wire);
}

#[test]
fn zero_capacity_reads_and_prefilled_readbuf_preserve_cursors() {
    let mut guard = Guard::new(Wire::new(GOLDEN.to_vec()), Vec::new());
    let (_, waker) = counting_waker();
    assert_eq!(
        read_once(&mut guard, &waker, 0),
        ReadResult::Data(Vec::new())
    );
    assert_eq!(guard.get_mut().reads, 0);
    assert_eq!(guard.headers_left, 32);
    let mut storage = [0; 32];
    let mut out = ReadBuf::new(&mut storage);
    out.put_slice(b"kept");
    assert!(matches!(
        Pin::new(&mut guard).poll_read(&mut Context::from_waker(&waker), &mut out),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(out.filled(), [b"kept".as_slice(), &GOLDEN[..6]].concat());
    assert_eq!(guard.bytes_left, 65_530);
    let mut received = GOLDEN[..6].to_vec();
    received.extend(collect(&mut guard, 17).unwrap());
    assert_eq!(received, GOLDEN);
}

#[test]
fn socket_read_errors_remain_errors_and_never_resynchronize() {
    for kind in [
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::Other,
    ] {
        let mut io = Wire::new(GOLDEN.to_vec());
        io.steps.extend([ReadStep::Bytes(1), ReadStep::Error(kind)]);
        let mut guard = Guard::new(io, Vec::new());
        let (_, waker) = counting_waker();
        assert_eq!(read_once(&mut guard, &waker, 17), ReadResult::Error(kind));
        let calls = guard.get_mut().reads;
        guard.begin_poll();
        assert_eq!(read_once(&mut guard, &waker, 17), ReadResult::Error(kind));
        assert_eq!(guard.get_mut().reads, calls);
        assert_eq!(guard.get_mut().offset, 1);
    }
}

#[test]
fn writes_flush_shutdown_and_vectored_writes_delegate_without_reading() {
    let payload: Vec<_> = (0..83).map(|n| n as u8).collect();
    let (_, waker) = counting_waker();
    for chunk in [1, 7, 17] {
        let mut io = Wire::new(Vec::new());
        io.chunk = chunk;
        io.alternate = true;
        let mut guard = Guard::new(io, GOLDEN.to_vec());
        let mut written = 0;
        for _ in 0..200 {
            let mut cx = Context::from_waker(&waker);
            match Pin::new(&mut guard).poll_write(&mut cx, &payload[written..]) {
                Poll::Pending => assert_eq!(guard.get_mut().output.len(), written),
                Poll::Ready(Ok(n)) => {
                    assert!(n > 0 && n <= chunk);
                    written += n;
                }
                other => panic!("写委托失败：{other:?}"),
            }
            if written == payload.len() {
                break;
            }
        }
        assert_eq!(written, payload.len());
        assert_eq!(guard.get_mut().output, payload);
        let buffers = [IoSlice::new(b"vec"), IoSlice::new(b"tored")];
        assert!(guard.is_write_vectored());
        assert!(
            Pin::new(&mut guard)
                .poll_write_vectored(&mut Context::from_waker(&waker), &buffers)
                .is_pending()
        );
        assert!(matches!(
            Pin::new(&mut guard).poll_write_vectored(&mut Context::from_waker(&waker), &buffers),
            Poll::Ready(Ok(n)) if n == chunk.min(8)
        ));
        assert_eq!(
            &guard.get_mut().output[payload.len()..],
            &b"vectored"[..chunk.min(8)]
        );
        assert_eq!(guard.get_mut().vectored_writes, 2);
        assert!(
            Pin::new(&mut guard)
                .poll_flush(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert!(matches!(
            Pin::new(&mut guard).poll_flush(&mut Context::from_waker(&waker)),
            Poll::Ready(Ok(()))
        ));
        assert!(
            Pin::new(&mut guard)
                .poll_shutdown(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert!(matches!(
            Pin::new(&mut guard).poll_shutdown(&mut Context::from_waker(&waker)),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(guard.get_mut().flushes, 2);
        assert_eq!(guard.get_mut().shutdowns, 2);
        assert_eq!(guard.get_mut().reads, 0);
        assert_eq!(guard.raw.prefix, GOLDEN);
        assert_eq!(guard.headers_left, 32);
        assert_eq!(guard.bytes_left, 65_536);
    }
}

#[test]
fn any_io_error_is_latched_but_get_mut_allows_final_underlying_shutdown() {
    let (_, waker) = counting_waker();
    for operation in 0..4 {
        let mut io = Wire::new(GOLDEN.to_vec());
        match operation {
            0 | 1 => io.write_error = Some(io::ErrorKind::BrokenPipe),
            2 => io.flush_error = Some(io::ErrorKind::BrokenPipe),
            _ => io.shutdown_error = Some(io::ErrorKind::BrokenPipe),
        }
        let mut guard = Guard::new(io, Vec::new());
        let mut cx = Context::from_waker(&waker);
        let failed = match operation {
            0 => Pin::new(&mut guard)
                .poll_write(&mut cx, b"x")
                .map_ok(|_| ()),
            1 => Pin::new(&mut guard)
                .poll_write_vectored(&mut cx, &[IoSlice::new(b"x")])
                .map_ok(|_| ()),
            2 => Pin::new(&mut guard).poll_flush(&mut cx),
            _ => Pin::new(&mut guard).poll_shutdown(&mut cx),
        };
        assert!(
            matches!(failed, Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
        );
        guard.begin_poll();
        assert_eq!(
            read_once(&mut guard, &waker, 17),
            ReadResult::Error(io::ErrorKind::BrokenPipe)
        );
        assert!(
            matches!(Pin::new(&mut guard).poll_write(&mut cx, b"x"), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
        );
        assert!(
            matches!(Pin::new(&mut guard).poll_write_vectored(&mut cx, &[IoSlice::new(b"x")]), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
        );
        assert!(
            matches!(Pin::new(&mut guard).poll_flush(&mut cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
        );
        assert!(
            matches!(Pin::new(&mut guard).poll_shutdown(&mut cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe)
        );
        assert_eq!(guard.get_mut().reads, 0);
        assert_eq!(guard.get_mut().writes, usize::from(operation == 0));
        assert_eq!(guard.get_mut().vectored_writes, usize::from(operation == 1));
        assert_eq!(guard.get_mut().flushes, usize::from(operation == 2));
        assert_eq!(guard.get_mut().shutdowns, usize::from(operation == 3));
        guard.get_mut().shutdown_error = None;
        assert!(matches!(
            Pin::new(guard.get_mut()).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
    }
}

#[tokio::test]
async fn duplex_write_backpressure_does_not_block_reads_or_replace_direction_wakers() {
    let (io, mut peer) = tokio::io::duplex(16);
    let mut guard = Guard::new(io, Vec::new());
    let (read_count, read_waker) = counting_waker();
    let (write_count, write_waker) = counting_waker();
    assert_eq!(read_once(&mut guard, &read_waker, 17), ReadResult::Pending);
    let outgoing = [0x5a; 48];
    let mut write_cx = Context::from_waker(&write_waker);
    assert!(matches!(
        Pin::new(&mut guard).poll_write(&mut write_cx, &outgoing),
        Poll::Ready(Ok(16))
    ));
    assert!(
        Pin::new(&mut guard)
            .poll_write(&mut write_cx, &outgoing[16..])
            .is_pending()
    );
    peer.write_all(&GOLDEN).await.unwrap();
    assert!(read_count.0.load(Ordering::SeqCst) > 0);
    let mut incoming = Vec::new();
    for _ in 0..4 {
        match read_once(&mut guard, &read_waker, 17) {
            ReadResult::Data(part) => incoming.extend(part),
            other => panic!("真实写背压不应阻塞已到达的读：{other:?}"),
        }
        if incoming.len() == GOLDEN.len() {
            break;
        }
    }
    assert_eq!(incoming, GOLDEN);
    assert_eq!(write_count.0.load(Ordering::SeqCst), 0);
    let mut delivered = Vec::new();
    let mut part = [0; 16];
    peer.read_exact(&mut part).await.unwrap();
    delivered.extend_from_slice(&part);
    assert!(write_count.0.load(Ordering::SeqCst) > 0);
    for offset in [16, 32] {
        assert!(matches!(
            Pin::new(&mut guard).poll_write(&mut write_cx, &outgoing[offset..]),
            Poll::Ready(Ok(16))
        ));
        peer.read_exact(&mut part).await.unwrap();
        delivered.extend_from_slice(&part);
    }
    assert_eq!(delivered, outgoing);
    guard.flush().await.unwrap();
    guard.shutdown().await.unwrap();
    assert_eq!(peer.read(&mut part).await.unwrap(), 0);
}

#[test]
fn deterministic_mixed_frames_survive_arbitrary_splits_short_reads_and_pending() {
    let mut seed = 0x4b1d_5a77_u32;
    let mut wire = Vec::new();
    for index in 0..96 {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let first = match index % 5 {
            0 => 0x82,
            1 => 0x02,
            2 => 0x80,
            3 => 0x89,
            _ => 0x8a,
        };
        let limit = if first & 8 != 0 { 126 } else { 300 };
        let length = (seed as usize) % limit;
        let payload: Vec<_> = (0..length)
            .map(|i| seed.wrapping_add(i as u32) as u8)
            .collect();
        wire.extend(frame(first, &payload));
    }
    for chunk in [1, 7, 17] {
        for split in [0, 1, 13, wire.len() / 3, wire.len() - 1, wire.len()] {
            let mut io = Wire::new(wire[split..].to_vec());
            io.chunk = chunk;
            io.alternate = true;
            let mut guard = Guard::new(io, wire[..split].to_vec());
            assert_eq!(collect(&mut guard, 17).unwrap(), wire);
        }
    }
}
