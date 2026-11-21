//! Additive REALITY client hook.
//!
//! This module only lets the caller replace the ClientHello legacy session ID
//! after the key share is generated. It does not authenticate REALITY, alter
//! certificates, relax verification, or change ordinary TLS behavior. The
//! caller's builder is responsible for the REALITY wire encoding and for
//! installing a certificate verifier that validates the temporary cert.
use alloc::{fmt, sync::Arc};
use core::fmt::Debug;

use crate::crypto::ActiveKeyExchange;
use crate::Error;

/// Builds the 32-byte REALITY legacy session ID.
///
/// `zero_hello` is the complete ClientHello handshake message (including its
/// four-byte handshake header) encoded with a zero-filled 32-byte session ID.
/// `key_share` is the exact active key exchange used in that ClientHello.
pub trait BuildsSessionId: Debug + Send + Sync {
    fn build(
        &self,
        random: [u8; 32],
        key_share: &dyn ActiveKeyExchange,
        zero_hello: &[u8],
    ) -> Result<[u8; 32], Error>;

    /// Receives the raw encoded ServerHello (including its four-byte
    /// handshake header) before certificate verification.
    ///
    /// REALITY's optional ML-DSA-65 extension signs
    /// `HMAC(auth_key, pubkey || rawCH || rawSH)`, so the caller needs the
    /// exact wire bytes. The default is a no-op for HMAC-only callers.
    fn server_hello(&self, _encoded: &[u8]) {}
}

/// Per-client REALITY session-ID builder.
pub struct Config {
    builder: Arc<dyn BuildsSessionId>,
    allow_hrr: bool,
}

impl Config {
    pub fn new(builder: Arc<dyn BuildsSessionId>) -> Self {
        Self {
            builder,
            allow_hrr: false,
        }
    }

    /// Allows a HelloRetryRequest when this hook is installed.
    ///
    /// The session ID chosen for the first ClientHello is carried into the
    /// second ClientHello unchanged. ECH and early data remain unsupported.
    pub fn new_allow_hrr(builder: Arc<dyn BuildsSessionId>) -> Self {
        Self {
            builder,
            allow_hrr: true,
        }
    }

    pub(crate) fn allows_hrr(&self) -> bool {
        self.allow_hrr
    }

    pub(crate) fn build(
        &self,
        random: [u8; 32],
        key_share: &dyn ActiveKeyExchange,
        zero_hello: &[u8],
    ) -> Result<[u8; 32], Error> {
        self.builder.build(random, key_share, zero_hello)
    }

    pub(crate) fn server_hello(&self, encoded: &[u8]) {
        self.builder.server_hello(encoded);
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("reality::client::Config([REDACTED])")
    }
}
