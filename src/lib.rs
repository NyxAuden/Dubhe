//! 独立服务端内核：协议处理与共享运行机制分离。
mod admin;
pub mod apply;
pub mod config;
pub(crate) mod connections;
pub mod convert;
pub mod dns;
pub mod export;
mod fallback;
pub mod forward;
pub mod geo;
pub(crate) mod mux;
pub mod outbound;
pub mod protocol;
pub(crate) mod reverse;
pub mod route;
pub mod runtime;
pub mod session;
pub(crate) mod sync;
pub mod telemetry;
pub mod tls;
pub(crate) mod transport;
pub mod udp;
pub(crate) mod util;

pub use config::Config;
pub use runtime::Server;

/// 仅测试使用的分配计数器。
///
/// 让「先复制再检查预算」这类改动可以被断言，而不是靠读代码相信。
/// 只影响 `cargo test --lib`；集成测试作为独立二进制，链接库里的
/// `global_allocator` 会被忽略，不会污染被测进程。
#[cfg(test)]
pub(crate) mod alloc_count {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
    };

    // 按线程计数：`cargo test --lib` 并行运行多个用例，进程级计数会被
    // 其它线程的分配污染，导致误报（实测让一条本该通过的断言失败）。
    thread_local! {
        static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
        static BYTES: Cell<usize> = const { Cell::new(0) };
    }

    pub struct Counting;

    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let _ = ALLOCATIONS.try_with(|value| value.set(value.get() + 1));
            let _ = BYTES.try_with(|value| value.set(value.get() + layout.size()));
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let _ = ALLOCATIONS.try_with(|value| value.set(value.get() + 1));
            let _ = BYTES
                .try_with(|value| value.set(value.get() + new_size.saturating_sub(layout.size())));
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static GLOBAL: Counting = Counting;

    /// 统计**当前线程**在这段同步代码里发生的分配次数与字节数。
    pub fn measure<T>(body: impl FnOnce() -> T) -> (T, usize, usize) {
        let before_allocations = ALLOCATIONS.with(Cell::get);
        let before_bytes = BYTES.with(Cell::get);
        let value = body();
        let allocations = ALLOCATIONS.with(Cell::get) - before_allocations;
        let bytes = BYTES.with(Cell::get) - before_bytes;
        (value, allocations, bytes)
    }
}

/// 仅供独立 fuzz 包启用的公开入口；生产构建不包含该模块。
#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    pub fn xhttp_parse_head(bytes: &[u8]) {
        crate::transport::xhttp::fuzz_parse_head(bytes);
    }

    pub fn xhttp_decode_uplink(encoded: &str) {
        crate::transport::xhttp::fuzz_decode_uplink(encoded);
    }

    pub fn grpc_decode_payload(payload: &[u8], multi: bool) {
        crate::transport::grpc::fuzz_decode_payload(payload, multi);
    }

    pub fn vmess_parse_header(bytes: &[u8], tls: bool) {
        crate::protocol::vmess::fuzz_parse_header(bytes, tls);
    }

    pub fn snell_parse_request(bytes: &[u8], version: u8) {
        crate::protocol::snell::fuzz_parse_request(bytes, version);
    }

    pub fn snell_decode_udp_request(bytes: &[u8]) {
        crate::protocol::snell::fuzz_decode_udp_request(bytes);
    }

    pub fn tuic_wire(bytes: &[u8]) {
        use crate::transport::tuic::wire;
        let _ = wire::decode_address(bytes);
        let _ = wire::decode_command_header(bytes);
        let _ = wire::decode_authenticate(bytes);
        let _ = wire::decode_udp_fixed(bytes);
        let _ = wire::decode_udp_datagram(bytes);
        let _ = wire::decode_udp_body(bytes);
    }
}
