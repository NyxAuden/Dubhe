//! 独立服务端内核：协议处理与共享运行机制分离。
mod admin;
pub mod config;
pub(crate) mod connections;
pub mod convert;
pub mod dns;
pub mod export;
mod fallback;
pub mod forward;
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
