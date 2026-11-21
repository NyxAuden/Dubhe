//! 精确 0.30.0 成熟库的独立 API 原型与分配测量。
//!
//! 本 integration-test binary 只有一个测试，避免多个测试互相污染全局分配计数。
//! 不复用生产护栏/适配器，不建立运行时或后台任务；测量范围见 websocket-memory.md。
#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    io::{self, Read, Write},
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use futures_util::Sink;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tungstenite::{
    Error, Message, WebSocket,
    protocol::{Role, WebSocketConfig, frame::coding::OpCode},
};

const MIB: usize = 1_048_576;
const READ_BUFFER: usize = 16_384;
const WRITE_BUFFER: usize = 131_072;
const SINGLE_WRITE: usize = 16_384;

#[global_allocator]
static ALLOCATOR: allocation::TrackingAllocator = allocation::TrackingAllocator;

// unsafe 只在本测试模块委托 System 的四个入口内；生产代码不使用此分配器。
mod allocation {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed},
    };

    pub struct TrackingAllocator;

    static ACTIVE: AtomicBool = AtomicBool::new(false);
    static LIVE: AtomicUsize = AtomicUsize::new(0);
    static PEAK: AtomicUsize = AtomicUsize::new(0);
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static REALLOCS: AtomicUsize = AtomicUsize::new(0);
    static LARGEST: AtomicUsize = AtomicUsize::new(0);
    static REQUESTED: AtomicUsize = AtomicUsize::new(0);

    fn allocated(size: usize) {
        let live = LIVE.fetch_add(size, Relaxed) + size;
        record(size, live, false);
    }

    fn record(size: usize, live: usize, reallocated: bool) {
        if ACTIVE.load(Relaxed) {
            CALLS.fetch_add(1, Relaxed);
            REQUESTED.fetch_add(size, Relaxed);
            LARGEST.fetch_max(size, Relaxed);
            PEAK.fetch_max(live, Relaxed);
            if reallocated {
                REALLOCS.fetch_add(1, Relaxed);
            }
        }
    }

    // SAFETY: 所有指针和 Layout 原样转交 System，不解引用用户指针、不改对齐、
    // 不分配计数器内存；原子计数不影响 GlobalAlloc 的所有权和失败约定。
    unsafe impl GlobalAlloc for TrackingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: GlobalAlloc 调用者保证 layout 有效，直接委托同一分配器。
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                allocated(layout.size());
            }
            pointer
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: 与 alloc 一样，且由 System 保证清零。
            let pointer = unsafe { System.alloc_zeroed(layout) };
            if !pointer.is_null() {
                allocated(layout.size());
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: 指针和原始 Layout 均由调用者保证来自本分配器。
            unsafe { System.dealloc(pointer, layout) };
            LIVE.fetch_sub(layout.size(), Relaxed);
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            // SAFETY: 保留 GlobalAlloc::realloc 对原始指针/Layout/new_size 的约定。
            let replacement = unsafe { System.realloc(pointer, layout, size) };
            if !replacement.is_null() {
                let live = if size >= layout.size() {
                    LIVE.fetch_add(size - layout.size(), Relaxed) + size - layout.size()
                } else {
                    LIVE.fetch_sub(layout.size() - size, Relaxed) - (layout.size() - size)
                };
                record(size, live, true);
            }
            // 失败时原块仍有效，不改变 LIVE。
            replacement
        }
    }

    pub struct Window {
        baseline: usize,
        checkpoint: usize,
    }

    pub struct Measurement {
        pub peak_delta: usize,
        pub retained_delta: i128,
        pub end_delta: i128,
        pub calls: usize,
        pub reallocations: usize,
        pub largest_request: usize,
        pub requested_total: usize,
    }

    impl Window {
        pub fn begin() -> Self {
            assert!(!ACTIVE.load(Relaxed), "测量窗口不能嵌套");
            let baseline = LIVE.load(Relaxed);
            PEAK.store(baseline, Relaxed);
            CALLS.store(0, Relaxed);
            REALLOCS.store(0, Relaxed);
            LARGEST.store(0, Relaxed);
            REQUESTED.store(0, Relaxed);
            ACTIVE.store(true, Relaxed);
            Self {
                baseline,
                checkpoint: baseline,
            }
        }

        pub fn checkpoint(&mut self) {
            self.checkpoint = LIVE.load(Relaxed);
        }

        pub fn finish(self) -> Measurement {
            ACTIVE.store(false, Relaxed);
            Measurement {
                peak_delta: PEAK.load(Relaxed).saturating_sub(self.baseline),
                retained_delta: self.checkpoint as i128 - self.baseline as i128,
                end_delta: LIVE.load(Relaxed) as i128 - self.baseline as i128,
                calls: CALLS.load(Relaxed),
                reallocations: REALLOCS.load(Relaxed),
                largest_request: LARGEST.load(Relaxed),
                requested_total: REQUESTED.load(Relaxed),
            }
        }
    }

    impl Drop for Window {
        fn drop(&mut self) {
            ACTIVE.store(false, Relaxed);
        }
    }
}

fn config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(READ_BUFFER)
        .write_buffer_size(0)
        .max_write_buffer_size(WRITE_BUFFER)
        .max_message_size(Some(MIB))
        .max_frame_size(Some(MIB))
        .accept_unmasked_frames(false)
}

#[derive(Clone, Copy)]
enum Block {
    Pending,
    IoWouldBlock,
}

struct Probe<'a> {
    input: &'a [u8],
    offset: usize,
    capture: Option<&'a mut Vec<u8>>,
    quota: usize,
    chunk: usize,
    blocked: usize,
    writes: usize,
    written: usize,
    mode: Block,
    writer: Option<Waker>,
}

impl<'a> Probe<'a> {
    fn new(input: &'a [u8], capture: Option<&'a mut Vec<u8>>) -> Self {
        Self {
            input,
            offset: 0,
            capture,
            quota: 0,
            chunk: usize::MAX,
            blocked: 0,
            writes: 0,
            written: 0,
            mode: Block::Pending,
            writer: None,
        }
    }

    fn unblock(&mut self) {
        self.quota = usize::MAX;
        if let Some(waker) = self.writer.take() {
            waker.wake();
        }
    }
}

impl Read for Probe<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.offset == self.input.len() {
            // 故意保持连接未结束，便于检查库保留的半帧及未完成消息。
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = out
            .len()
            .min(READ_BUFFER)
            .min(self.input.len() - self.offset);
        out[..n].copy_from_slice(&self.input[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}

impl Write for Probe<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.quota == 0 {
            self.blocked += 1;
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let n = bytes.len().min(self.quota).min(self.chunk);
        if let Some(capture) = self.capture.as_mut() {
            capture.extend_from_slice(&bytes[..n]);
        }
        self.written += n;
        self.quota -= n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for Probe<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut scratch = [0; READ_BUFFER];
        let n = out.remaining().min(scratch.len());
        match Read::read(this, &mut scratch[..n]) {
            Ok(n) => {
                out.put_slice(&scratch[..n]);
                Poll::Ready(Ok(()))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl AsyncWrite for Probe<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Write::write(this, bytes) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                this.writer = Some(cx.waker().clone());
                match this.mode {
                    Block::Pending => Poll::Pending,
                    Block::IoWouldBlock => Poll::Ready(Err(error)),
                }
            }
            result => Poll::Ready(result),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct CountWake(AtomicUsize);
impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn raw_async<'a>(probe: Probe<'a>) -> WebSocketStream<Probe<'a>> {
    let mut future = pin!(WebSocketStream::from_raw_socket(
        probe,
        Role::Server,
        Some(config())
    ));
    match std::future::Future::poll(future.as_mut(), &mut Context::from_waker(Waker::noop())) {
        Poll::Ready(socket) => socket,
        Poll::Pending => panic!("from_raw_socket 不应执行握手或等待网络 IO"),
    }
}

// 独立的线格式金样：不调用库的 encoder 来验证同一库的输出。
fn server_binary(payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x82];
    match payload.len() {
        0..=125 => wire.push(payload.len() as u8),
        126..=65_535 => {
            wire.push(126);
            wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        _ => {
            wire.push(127);
            wire.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
    }
    wire.extend_from_slice(payload);
    wire
}

fn async_wouldblock_accepts_exactly_once() {
    for mode in [Block::Pending, Block::IoWouldBlock] {
        for chunk in [1, 7, 17] {
            let payload = b"accepted-once-after-partial-frame";
            let expected = server_binary(payload);
            let mut output = Vec::new();
            let mut probe = Probe::new(&[], Some(&mut output));
            probe.mode = mode;
            probe.chunk = chunk;
            probe.quota = 3; // 已写出半个帧，再出现底层 Pending/Io(WouldBlock)。
            let mut socket = raw_async(probe);
            let count = Arc::new(CountWake::default());
            let waker = Waker::from(count.clone());
            let mut cx = Context::from_waker(&waker);
            assert!(matches!(
                Pin::new(&mut socket).poll_ready(&mut cx),
                Poll::Ready(Ok(()))
            ));
            Pin::new(&mut socket)
                .start_send(Message::binary(payload.to_vec()))
                .expect("Io(WouldBlock) 在 tokio 封装中表示消息已接受，不能重投");
            assert_eq!(socket.get_ref().written, 3);
            assert_eq!(
                socket.get_ref().capture.as_ref().unwrap().as_slice(),
                &expected[..3]
            );
            assert!(socket.get_ref().blocked > 0);
            for _ in 0..3 {
                assert!(Pin::new(&mut socket).poll_ready(&mut cx).is_pending());
                assert!(Pin::new(&mut socket).poll_flush(&mut cx).is_pending());
                assert_eq!(socket.get_ref().written, 3);
            }
            socket.get_mut().unblock();
            assert!(count.0.load(Ordering::Relaxed) > 0);
            assert!(matches!(
                Pin::new(&mut socket).poll_ready(&mut cx),
                Poll::Ready(Ok(()))
            ));
            assert!(matches!(
                Pin::new(&mut socket).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(
                socket.get_ref().capture.as_ref().unwrap().as_slice(),
                expected
            );
            // 再 flush 不得重复已接受的消息；随后新消息也只能出现一次。
            assert!(matches!(
                Pin::new(&mut socket).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
            Pin::new(&mut socket)
                .start_send(Message::binary(b"next".to_vec()))
                .unwrap();
            assert!(matches!(
                Pin::new(&mut socket).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
            drop(socket);
            assert_eq!(output, [expected, server_binary(b"next")].concat());
        }
    }
}

fn sync_write_buffer_full_returns_unaccepted_frame() {
    let first = vec![0x41; SINGLE_WRITE];
    let rejected_payload = vec![0x42; SINGLE_WRITE];
    let mut output = Vec::new();
    let mut socket = WebSocket::from_raw_socket(
        Probe::new(&[], Some(&mut output)),
        Role::Server,
        Some(config()),
    );
    // 七个 16384+4 字节帧可入 128 KiB 队列，第八个不行。
    for _ in 0..7 {
        assert!(matches!(socket.write(Message::binary(first.clone())),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock));
    }
    let calls = socket.get_ref().writes;
    let returned = match socket.write(Message::binary(rejected_payload.clone())) {
        Err(Error::WriteBufferFull(message)) => *message,
        other => panic!("应在入队前返回未接受帧：{other:?}"),
    };
    let Message::Frame(frame) = &returned else {
        panic!("0.30.0 返回的是 Message::Frame，不是原始 Message::Binary");
    };
    assert_eq!(frame.payload(), rejected_payload);
    assert_eq!(
        frame.header().opcode,
        OpCode::Data(tungstenite::protocol::frame::coding::Data::Binary)
    );
    assert_eq!(socket.get_ref().writes, calls, "拒绝发生在写底层之前");
    assert_eq!(socket.get_ref().written, 0);
    socket.get_mut().chunk = 7;
    socket.get_mut().unblock();
    socket.flush().unwrap();
    let first_wire = server_binary(&first).repeat(7);
    assert_eq!(
        socket.get_ref().capture.as_ref().unwrap().as_slice(),
        first_wire
    );
    // 只重投 WriteBufferFull 返回的未接受帧；不能重投前七个 WouldBlock 已接收帧。
    socket.write(returned).unwrap();
    socket.flush().unwrap();
    socket.flush().unwrap();
    drop(socket);
    assert_eq!(
        output,
        [first_wire, server_binary(&rejected_payload)].concat()
    );
}

fn client_header(wire: &mut Vec<u8>, first: u8, length: usize) {
    wire.push(first);
    match length {
        0..=125 => wire.push(0x80 | length as u8),
        126..=65_535 => {
            wire.push(0xfe);
            wire.extend_from_slice(&(length as u16).to_be_bytes());
        }
        _ => {
            wire.push(0xff);
            wire.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    wire.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
}

fn client_frame(wire: &mut Vec<u8>, first: u8, length: usize, byte: u8) {
    client_header(wire, first, length);
    wire.extend((0..length).map(|i| byte ^ [0x12, 0x34, 0x56, 0x78][i % 4]));
}

fn fragmented(wire: &mut Vec<u8>, text: bool) {
    // 特意越过多个 Vec 几何增长边界；总消息载荷恰好 1 MiB。
    let portions = [1, 65_535, 65_537, 131_073, 262_145];
    let mut total = 0;
    for (index, length) in portions.into_iter().enumerate() {
        client_frame(
            wire,
            if index == 0 {
                if text { 0x01 } else { 0x02 }
            } else {
                0x00
            },
            length,
            b'a',
        );
        total += length;
    }
    client_frame(wire, 0x80, MIB - total, b'a');
}

fn queue_bounded_writes(socket: &mut WebSocket<Probe<'_>>) {
    for _ in 0..7 {
        assert!(
            matches!(socket.write(Message::binary(vec![0x55; SINGLE_WRITE])),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock)
        );
    }
    assert!(matches!(
        socket.write(Message::binary(vec![0x66; SINGLE_WRITE])),
        Err(Error::WriteBufferFull(_))
    ));
    assert_eq!(socket.get_ref().written, 0);
}

fn memory_sample(name: &'static str, wire: &[u8], text: bool, partial_next: bool) {
    // 输入夹具在窗口外分配且只借用；输出不捕获、不分配，只有库持有的缓冲计入增量。
    let mut window = allocation::Window::begin();
    let mut socket =
        WebSocket::from_raw_socket(Probe::new(wire, None), Role::Server, Some(config()));
    queue_bounded_writes(&mut socket);
    let held = socket.read().expect("完整的 1 MiB 金样消息");
    match &held {
        Message::Binary(bytes) if !text => {
            assert_eq!(bytes.len(), MIB);
            assert!(bytes.iter().all(|byte| *byte == b'a'));
        }
        Message::Text(bytes) if text => {
            assert_eq!(bytes.len(), MIB);
            assert!(bytes.as_bytes().iter().all(|byte| *byte == b'a'));
        }
        other => panic!("消息类型与夹具不符：{other:?}"),
    }
    let mut retained_ping = None;
    if partial_next {
        // 比生产适配器更保守的压力组合：保留完成消息仍继续读下一消息，
        // 同时持有分片累积、一个 Pong/控制载荷以及尚未收全的大帧。
        let mut stopped = false;
        for _ in 0..8 {
            match socket.read() {
                Ok(message @ Message::Ping(_)) => retained_ping = Some(message),
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                    stopped = true;
                    break;
                }
                other => panic!("半帧应保留到 WouldBlock：{other:?}"),
            }
        }
        assert!(stopped);
        assert!(retained_ping.is_some());
        assert_eq!(socket.get_ref().offset, wire.len());
    }
    window.checkpoint();
    drop(retained_ping);
    drop(held);
    drop(socket);
    let measurement = window.finish();
    assert!(measurement.calls > 0);
    assert!(measurement.peak_delta >= READ_BUFFER);
    // 这只是三个固定夹具的分配回归阈值，不是任意连接/RSS 的证明。
    assert!(
        measurement.peak_delta <= 32 * MIB,
        "固定库夹具超过源码容量模型预算"
    );
    println!(
        "WS_LIBRARY_ALLOC name={name} peak_delta={} retained_delta={} end_delta={} calls={} reallocations={} largest_request={} requested_total={}",
        measurement.peak_delta,
        measurement.retained_delta,
        measurement.end_delta,
        measurement.calls,
        measurement.reallocations,
        measurement.largest_request,
        measurement.requested_total,
    );
}

#[test]
fn websocket_library_api_and_allocations() {
    async_wouldblock_accepts_exactly_once();
    sync_write_buffer_full_returns_unaccepted_frame();

    let mut single = Vec::new();
    client_frame(&mut single, 0x82, MIB, b'a');
    memory_sample("single_binary_1mib", &single, false, false);

    for text in [false, true] {
        let mut wire = Vec::new();
        fragmented(&mut wire, text);
        // 第二条消息尚未完成，累积 Vec 越过 512 KiB；控制帧插入后，
        // 下一个合法 1 MiB continuation 只到达 64 字节，促使库提前 reserve。
        client_frame(&mut wire, 0x02, 524_289, b'b');
        client_frame(&mut wire, 0x00, 1, b'b');
        client_frame(&mut wire, 0x89, 125, b'p');
        client_header(&mut wire, 0x80, MIB);
        wire.extend((0..64).map(|i| b'c' ^ [0x12, 0x34, 0x56, 0x78][i % 4]));
        memory_sample(
            if text {
                "fragmented_text_and_reserved_next_frame"
            } else {
                "fragmented_binary_and_reserved_next_frame"
            },
            &wire,
            text,
            true,
        );
    }
}
