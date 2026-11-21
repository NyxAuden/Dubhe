//! 当前 VMess AEAD 入站的认证、有限正文与进程内重放保护。
pub(crate) mod body;
pub(crate) mod client;
pub(crate) mod crypto;
mod header;
pub(crate) mod replay;

#[cfg(feature = "fuzzing")]
pub(crate) use header::fuzz_parse_header;
pub(crate) use header::{Accepted, Mode, Policy, Prepared};
