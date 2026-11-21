//! Snell v6 默认记录模式（`default` / shaped）的核心编解码。
//!
//! 本文件按 sing-snell `snellv6` 的公开 wire 行为独立实现，不包含 Go 源码，
//! 也不依赖运行时、配置或既有 Snell v4/v5 模块。后续接入时只需把本文件
//! 声明为 `pub(crate) mod snell_v6;`，再按现有异步记录层包装 `ShapedWriter`
//! 与 `ShapedReader` 即可。
//!
//! 已实现的范围：
//!
//! * [`Profile::new`]：BLAKE2b-256 的 profile secret + SplitMix64 PRF 派生
//!   全部 default-mode 参数（padding、prefix、salt block、mixing、chunk/write
//!   策略）。
//! * [`ShapedWriter`]：首记录 salt block、record prefix、加密头、随机化
//!   padding、padding/payload mixing、nonce 递增、动态 chunk 切分。
//! * [`ShapedReader`]：增量缓冲解码，salt block 还原、prefix/header 校验、
//!   mixing 逆变换、payload 解密、零块（逻辑 EOF）识别。
//!
//! 未实现（保持与上游 `mode.go` 一致的名字，但本文件只提供 default codec）：
//! `unshaped` 与 `unsafe-raw`。它们不是 default 的替代实现，接入时应显式
//! 选择；本模块不会用空 padding 或明文冒充 default。
#![allow(dead_code)]

use std::io;

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2b, Digest, digest::consts::U32};

// ---------------------------------------------------------------------------
// Snell v6 常量（与上游 `snell.go` / `mode.go` 一致）
// ---------------------------------------------------------------------------

/// 记录头版本。
pub(crate) const HEADER_VERSION: u8 = 0x04;
/// 明文头长度：version + 2 个保留字节 + padding 长度 + payload 长度。
pub(crate) const HEADER_PLAIN_LEN: usize = 7;
/// AEAD 认证标签长度。
pub(crate) const TAG_LEN: usize = 16;
/// 加密头长度。
pub(crate) const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + TAG_LEN;
/// 每个方向首记录前的 salt 长度。
pub(crate) const SALT_LEN: usize = 16;
/// nonce 长度。
pub(crate) const NONCE_LEN: usize = 12;
/// v6 单个记录允许的最大明文 payload。
pub(crate) const MAX_PAYLOAD: usize = 0xffff;

/// v6 记录模式。仅 `Default` 在本文件实现。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// 默认 shaped 模式。
    Default,
    /// 无 padding 的 AEAD 模式（未在本文件实现）。
    Unshaped,
    /// 明文模式（未在本文件实现）。
    UnsafeRaw,
}

impl Mode {
    /// 与上游 `ParseMode` 相同的名字映射；空名字即 default。
    pub(crate) fn parse(name: &str) -> io::Result<Self> {
        match name {
            "" | "default" => Ok(Self::Default),
            "unshaped" => Ok(Self::Unshaped),
            "unsafe-raw" => Ok(Self::UnsafeRaw),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Snell v6 未知记录模式",
            )),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Unshaped => "unshaped",
            Self::UnsafeRaw => "unsafe-raw",
        }
    }

    /// 本文件是否提供该模式的 codec。
    pub(crate) fn is_implemented(self) -> bool {
        matches!(self, Self::Default)
    }
}

// ---------------------------------------------------------------------------
// profile 派生
// ---------------------------------------------------------------------------

const GOLDEN_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;
const MAX_EXTRA_PADDING: usize = 0x02da;

const LABEL_PADDING: u32 = 0;
const LABEL_BIT_PERCENT: u32 = 1;
const LABEL_MOTIF: u32 = 2;
const LABEL_MIX_OFFSET: u32 = 3;
const LABEL_SALT: u32 = 3;
const LABEL_PROFILE_ID: u32 = 5;
const LABEL_GENERATOR: u32 = 6;
const LABEL_PAD_MIN: u32 = 7;
const LABEL_PAD_MAX: u32 = 8;
const LABEL_PAD_COUNT: u32 = 9;
const LABEL_PAD_INTERVAL: u32 = 10;
const LABEL_SMALL_LIMIT: u32 = 11;
const LABEL_BIT_MIN: u32 = 12;
const LABEL_BIT_MAX: u32 = 13;
const LABEL_PREFIX_MIN: u32 = 14;
const LABEL_PREFIX_MAX: u32 = 15;
const LABEL_MIX_MODE: u32 = 16;
const LABEL_MIX_ROUNDS: u32 = 17;
const LABEL_MIX_STRIDE: u32 = 18;
const LABEL_MIX_OFFSET_BASE: u32 = 19;
const LABEL_MIX_BLOCK: u32 = 20;
const LABEL_CHUNK_POLICY: u32 = 21;
const LABEL_CHUNK_INITIAL: u32 = 22;
const LABEL_CHUNK_FIRST_CAP: u32 = 22;
const LABEL_CHUNK_MAX: u32 = 23;
const LABEL_CHUNK_STEP: u32 = 24;
const LABEL_CHUNK_JITTER: u32 = 25;
const LABEL_CHUNK_BUCKET: u32 = 26;
const LABEL_IDLE_RESET: u32 = 27;
const LABEL_WRITE_POLICY: u32 = 28;
const LABEL_WRITE_FIRST: u32 = 29;
const LABEL_WRITE_BUCKET: u32 = 30;
const LABEL_WRITE_SEQ: u32 = 31;
const LABEL_WRITE_JITTER: u32 = 32;
const LABEL_RECORD_PREFIX: u32 = 33;
const LABEL_PAYLOAD_PAD: u32 = 34;
const LABEL_WRITE_TARGET: u32 = 35;
const LABEL_WRITE_JITTER_V: u32 = 36;
const LABEL_WRITE_NEXT: u32 = 37;
const LABEL_CHUNK_SIZE: u32 = 38;
const LABEL_CHUNK_JITTER_V: u32 = 39;

const HANDSHAKE_DOMAIN: u32 = 0x7053;
const MIX_HANDSHAKE_DOMAIN: u32 = 0x51a7;
const CHUNK_INITIAL_DOMAIN: u32 = 0xf17c;

const NS_SEED_PROFILE: u64 = 0xb46c_2e7d_9a15_38f1;
const NS_SEED_PREFIX: u64 = 0x5d92_17c0_83e6_4ab9;
const NS_SEED_MOTIF: u64 = 0xa71f_0c54_d839_6e2b;
const NS_SEED_SALT: u64 = 0x3e8a_91b5_2740_f6cd;
const NS_SEED_MIX: u64 = 0xc9f4_260b_7d1e_835a;
const NS_SEED_CHUNK: u64 = 0x62d0_b5e1_9c4a_783f;
const NS_SEED_WRITE: u64 = 0x917b_3c48_e6a2_05d4;

const DOMAIN_MUL: u64 = 0xd6e8_feb8_6659_fd93;
const NAMESPACE_ADD: u64 = 0xa076_1d64_78bd_642f;
const COEF_B: u64 = 0x5899_65cc_7537_4cc3;
const ADD_B: u64 = 0x33a2_13ec_50ff_e2e9;
const COEF_A: u64 = 0xe703_7ed1_a0b4_28db;
const ADD_A: u64 = 0x8f39_07f7_b2b8_0c35;

const SALT_NS_XOR: u64 = 0xdaa6_6d2c_7ddf_743f;

/// `blake2b(profileSeed || psk, 32)` 的前缀。
const PROFILE_SEED: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e,
    0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];

/// generator 0 的低半字节旋转表。
const BIT_ROTATE_TABLE: [u8; 128] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18, 0x24,
    0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70, 0xe0,
    0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78, 0xf0,
    0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f, 0x1f,
    0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7, 0xdb,
    0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f,
];

fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x
}

fn prf_fold(namespace: u64, label: u32, a: u64, b: u64) -> u32 {
    let x = namespace
        ^ b.wrapping_mul(COEF_B).wrapping_add(ADD_B)
        ^ u64::from(label).wrapping_mul(GOLDEN_GAMMA)
        ^ a.wrapping_mul(COEF_A).wrapping_add(ADD_A);
    let y = splitmix64(x);
    (y ^ (y >> 32)) as u32
}

fn pick(raw: u32, lo: usize, hi: usize) -> usize {
    debug_assert!(hi >= lo);
    lo + (u64::from(raw) % (hi - lo + 1) as u64) as usize
}

fn pick_u32(raw: u32, lo: u32, hi: u32) -> u32 {
    debug_assert!(hi >= lo);
    lo + raw % (hi - lo + 1)
}

fn derive_namespace(secret: &[u8; 32], label: u32, seed: u64) -> u64 {
    let s0 = u64::from_le_bytes(secret[0..8].try_into().expect("8 字节"));
    let s1 = u64::from_le_bytes(secret[8..16].try_into().expect("8 字节"));
    let s2 = u64::from_le_bytes(secret[16..24].try_into().expect("8 字节"));
    let s3 = u64::from_le_bytes(secret[24..32].try_into().expect("8 字节"));
    let mixed = u64::from(label).wrapping_mul(DOMAIN_MUL)
        ^ seed.wrapping_add(NAMESPACE_ADD)
        ^ s0
        ^ s1.wrapping_add(GOLDEN_GAMMA)
        ^ s2.rotate_left(17)
        ^ s3.rotate_right(11);
    splitmix64(mixed)
}

#[derive(Clone, Debug)]
struct Namespaces {
    profile: u64,
    prefix: u64,
    motif: u64,
    salt: u64,
    mix: u64,
    chunk: u64,
    write: u64,
}

impl Namespaces {
    fn new(secret: &[u8; 32]) -> Self {
        Self {
            profile: derive_namespace(secret, LABEL_PROFILE_ID, NS_SEED_PROFILE),
            prefix: derive_namespace(secret, LABEL_PADDING, NS_SEED_PREFIX),
            motif: derive_namespace(secret, LABEL_MOTIF, NS_SEED_MOTIF),
            salt: derive_namespace(secret, LABEL_SALT, NS_SEED_SALT),
            mix: derive_namespace(secret, LABEL_MIX_MODE, NS_SEED_MIX),
            chunk: derive_namespace(secret, LABEL_CHUNK_POLICY, NS_SEED_CHUNK),
            write: derive_namespace(secret, LABEL_WRITE_POLICY, NS_SEED_WRITE),
        }
    }

    fn for_label(&self, label: u32) -> u64 {
        match label {
            LABEL_PADDING | LABEL_BIT_PERCENT | LABEL_PREFIX_MIN | LABEL_PREFIX_MAX
            | LABEL_RECORD_PREFIX | LABEL_PAYLOAD_PAD => self.prefix,
            LABEL_MOTIF => self.motif,
            LABEL_MIX_OFFSET
            | LABEL_MIX_MODE
            | LABEL_MIX_ROUNDS
            | LABEL_MIX_STRIDE
            | LABEL_MIX_OFFSET_BASE
            | LABEL_MIX_BLOCK => self.mix,
            LABEL_CHUNK_POLICY | LABEL_CHUNK_INITIAL | LABEL_CHUNK_MAX | LABEL_CHUNK_STEP
            | LABEL_CHUNK_JITTER | LABEL_CHUNK_BUCKET | LABEL_CHUNK_SIZE | LABEL_CHUNK_JITTER_V => {
                self.chunk
            }
            LABEL_WRITE_POLICY | LABEL_WRITE_FIRST | LABEL_WRITE_BUCKET | LABEL_WRITE_SEQ
            | LABEL_WRITE_JITTER | LABEL_WRITE_TARGET | LABEL_WRITE_JITTER_V | LABEL_WRITE_NEXT => {
                self.write
            }
            _ => self.profile,
        }
    }

    fn prf32(&self, label: u32, a: u32, b: u32) -> u32 {
        prf_fold(self.for_label(label), label, u64::from(a), u64::from(b))
    }

    fn prf_static(&self, label: u32, domain: u32) -> u32 {
        prf_fold(self.for_label(label), label, 0, u64::from(domain))
    }

    /// 以 SplitMix64 流填充任意长度的伪随机字节。
    fn prf_bytes(&self, label: u32, a: u32, output: &mut [u8]) {
        let mut seed = self.for_label(label)
            ^ u64::from(a)
                .wrapping_mul(DOMAIN_MUL)
                .wrapping_add(0xb57d_e1f3_f82c_b33f)
            ^ u64::from(label).wrapping_mul(0xa24b_aed4_963e_e407)
            ^ (output.len() as u64)
                .wrapping_mul(0x1656_67b1_9e37_79f9)
                .wrapping_add(0x0d4c_d3e7_b14a_36d7);
        let mut offset = 0;
        while offset < output.len() {
            seed = seed.wrapping_add(GOLDEN_GAMMA);
            let block = splitmix64(seed);
            for shift in (0..64).step_by(8) {
                if offset == output.len() {
                    break;
                }
                output[offset] = (block >> shift) as u8;
                offset += 1;
            }
        }
    }
}

/// 每个 PSK 的 Snell v6 default-mode 参数。
#[derive(Clone, Debug)]
pub(crate) struct Profile {
    namespaces: Namespaces,

    generator: u32,
    pad_min: usize,
    pad_max: usize,
    pad_count: usize,
    pad_interval: usize,
    small_limit: usize,
    bit_min: u32,
    bit_max: u32,
    prefix_min_record: usize,
    prefix_max_record: usize,
    mix_mode: u32,
    mix_rounds: u32,
    mix_stride: usize,
    mix_offset_base: usize,
    mix_block: usize,
    chunk_policy: u32,
    chunk_initial: usize,
    first_record_cap: usize,
    chunk_max: usize,
    chunk_step: usize,
    chunk_jitter: usize,
    idle_reset_sec: i64,
    write_policy: u32,
    write_first: usize,
    chunk_buckets: [usize; 8],
    write_buckets: [usize; 8],
    write_seq: [usize; 8],
    write_jitter: usize,
    write_jitter_pct: usize,
    g1: usize,
    g2: usize,
    g3: usize,
    g4: usize,
    g5: usize,
    g6: usize,

    salt_block_len: usize,
    mix_stride_handshake: usize,
    mix_rounds_handshake: u32,
}

impl Profile {
    /// 由 PSK 派生 default-mode profile。
    pub(crate) fn new(psk: &[u8]) -> Self {
        let secret = profile_secret(psk);
        let namespaces = Namespaces::new(&secret);

        let pad_min = pick(namespaces.prf_static(LABEL_PAD_MIN, 0), 0x18, 0xa0);
        let pad_max = (pad_min + pick(namespaces.prf_static(LABEL_PAD_MAX, 0), 0xa0, 0x3c0))
            .min(MAX_EXTRA_PADDING);

        let mut prefix_min_hs = pick(
            namespaces.prf_static(LABEL_PREFIX_MIN, HANDSHAKE_DOMAIN),
            0x10,
            0x60,
        );
        let prefix_max_hs = (prefix_min_hs
            + pick(
                namespaces.prf_static(LABEL_PREFIX_MAX, HANDSHAKE_DOMAIN),
                0x10,
                0xa0,
            ))
        .min(0x80);
        prefix_min_hs = prefix_min_hs.min(prefix_max_hs);
        let salt_prefix_len = pick(
            namespaces.prf_static(LABEL_RECORD_PREFIX, HANDSHAKE_DOMAIN),
            prefix_min_hs,
            prefix_max_hs,
        );
        let salt_block_len = SALT_LEN + salt_prefix_len;

        let mix_rounds_handshake = pick_u32(
            namespaces.prf_static(LABEL_MIX_ROUNDS, MIX_HANDSHAKE_DOMAIN),
            1,
            4,
        );
        let mix_stride_handshake = pick(
            namespaces.prf_static(LABEL_MIX_STRIDE, MIX_HANDSHAKE_DOMAIN),
            0x11,
            0xfb,
        );

        let mut prefix_min_record = pick(namespaces.prf_static(LABEL_PREFIX_MIN, 0), 0x08, 0x50);
        let prefix_max_record = (prefix_min_record
            + pick(namespaces.prf_static(LABEL_PREFIX_MAX, 0), 0x10, 0xa0))
        .min(0x80);
        prefix_min_record = prefix_min_record.min(prefix_max_record);

        let chunk_initial =
            pick(namespaces.prf_static(LABEL_CHUNK_INITIAL, 0), 0x200, 0x05b4).clamp(0x60, 0x05b4);
        let first_record_cap = pick(
            namespaces.prf_static(LABEL_CHUNK_FIRST_CAP, CHUNK_INITIAL_DOMAIN),
            0x100,
            0x300,
        )
        .min(chunk_initial.min(0x300))
        .max(0x100);
        let chunk_max =
            pick(namespaces.prf_static(LABEL_CHUNK_MAX, 0), 0x2000, 0x3fff).max(chunk_initial);

        let mut chunk_buckets = [0usize; 8];
        let mut write_buckets = [0usize; 8];
        let mut write_seq = [0usize; 8];
        for (index, ((chunk_bucket, write_bucket), write_sequence)) in chunk_buckets
            .iter_mut()
            .zip(write_buckets.iter_mut())
            .zip(write_seq.iter_mut())
            .enumerate()
        {
            let index = index as u32;
            *chunk_bucket = pick(
                namespaces.prf_static(LABEL_CHUNK_BUCKET, index),
                0x1000,
                chunk_max,
            );
            *write_bucket = pick(
                namespaces.prf_static(LABEL_WRITE_BUCKET, index),
                0x140,
                0x05b4,
            );
            *write_sequence = pick(namespaces.prf_static(LABEL_WRITE_SEQ, index), 0x168, 0x05b4);
        }

        Self {
            generator: namespaces.prf_static(LABEL_GENERATOR, 0) & 3,
            pad_min,
            pad_max,
            pad_count: pick_u32(namespaces.prf_static(LABEL_PAD_COUNT, 0), 2, 8) as usize,
            pad_interval: pick_u32(namespaces.prf_static(LABEL_PAD_INTERVAL, 0), 2, 0x0b) as usize,
            small_limit: pick(namespaces.prf_static(LABEL_SMALL_LIMIT, 0), 0x60, 0x300),
            bit_min: pick_u32(namespaces.prf_static(LABEL_BIT_MIN, 0), 0x18, 0x29),
            bit_max: pick_u32(namespaces.prf_static(LABEL_BIT_MAX, 0), 0x3a, 0x4c),
            prefix_min_record,
            prefix_max_record,
            mix_mode: namespaces.prf_static(LABEL_MIX_MODE, 0) % 3,
            mix_rounds: pick_u32(namespaces.prf_static(LABEL_MIX_ROUNDS, 0), 1, 3),
            mix_stride: pick(namespaces.prf_static(LABEL_MIX_STRIDE, 0), 2, 13),
            mix_offset_base: pick(namespaces.prf_static(LABEL_MIX_OFFSET_BASE, 0), 0, 15),
            mix_block: pick(namespaces.prf_static(LABEL_MIX_BLOCK, 0), 8, 0x40),
            chunk_policy: namespaces.prf_static(LABEL_CHUNK_POLICY, 0) % 3,
            chunk_initial,
            first_record_cap,
            chunk_max,
            chunk_step: pick(namespaces.prf_static(LABEL_CHUNK_STEP, 0), 0x400, 0x1000).min(0x0b68),
            chunk_jitter: pick(namespaces.prf_static(LABEL_CHUNK_JITTER, 0), 0x10, 0xc0).min(0x0b6),
            idle_reset_sec: pick(namespaces.prf_static(LABEL_IDLE_RESET, 0), 0x0c, 0x5a) as i64,
            write_policy: namespaces.prf_static(LABEL_WRITE_POLICY, 0) % 3,
            write_first: pick_u32(namespaces.prf_static(LABEL_WRITE_FIRST, 0), 4, 8) as usize,
            chunk_buckets,
            write_buckets,
            write_seq,
            write_jitter: pick(namespaces.prf_static(LABEL_WRITE_JITTER, 0), 0x08, 0x60),
            write_jitter_pct: pick(namespaces.prf_static(LABEL_WRITE_POLICY, 0x504c), 8, 0x30),
            g1: pick(namespaces.prf_static(LABEL_GENERATOR, 1), 0x18, 0x80),
            g2: pick(namespaces.prf_static(LABEL_GENERATOR, 2), 0x10, 0x60),
            g3: pick(namespaces.prf_static(LABEL_GENERATOR, 3), 0x10, 0x60),
            g4: pick(namespaces.prf_static(LABEL_GENERATOR, 4), 0x00, 0x09),
            g5: pick(namespaces.prf_static(LABEL_GENERATOR, 5), 0x01, 0x08),
            g6: pick(namespaces.prf_static(LABEL_GENERATOR, 6), 0x07, 0x17),
            salt_block_len,
            mix_stride_handshake,
            mix_rounds_handshake,
            namespaces,
        }
    }

    /// 首记录 salt block 的总长度（salt 本身 + 伪随机前缀）。
    pub(crate) fn salt_block_len(&self) -> usize {
        self.salt_block_len
    }

    /// 当前 record 的 prefix 长度。
    pub(crate) fn record_prefix_len(&self, seq: u32) -> usize {
        pick(
            self.namespaces.prf32(LABEL_RECORD_PREFIX, seq, 0),
            self.prefix_min_record,
            self.prefix_max_record,
        )
    }

    fn chunk_payload_limit(&self, seq: u32, chunk_size: usize) -> usize {
        let chunk_size = if chunk_size == 0 {
            self.chunk_initial
        } else {
            chunk_size
        };
        let size = match self.chunk_policy {
            1 => {
                let index = self
                    .namespaces
                    .prf32(LABEL_CHUNK_SIZE, seq, chunk_size as u32)
                    as usize
                    % self.chunk_buckets.len();
                self.chunk_buckets[index]
            }
            2 => {
                let raw = self
                    .namespaces
                    .prf32(LABEL_CHUNK_JITTER_V, seq, chunk_size as u32);
                let span = (self.chunk_jitter as u32).wrapping_mul(2).wrapping_add(1);
                let jitter = (raw % span) as isize - self.chunk_jitter as isize;
                (chunk_size as isize + jitter).max(0) as usize
            }
            _ => chunk_size,
        };
        size.clamp(0x40, self.chunk_max)
    }

    fn next_chunk_size(&self, chunk_size: usize) -> usize {
        if chunk_size == 0 {
            self.chunk_initial
        } else {
            (chunk_size + self.chunk_step).min(self.chunk_max)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn padding_len(
        &self,
        seq: u32,
        payload_len: usize,
        prefix_len: usize,
        salt_prefix_len: usize,
        total_len: usize,
    ) -> usize {
        let mut padding_len = 0;
        if (seq as usize) < self.pad_count
            || (payload_len > 0 && payload_len <= self.small_limit)
            || (self.pad_interval > 0 && (seq as usize).is_multiple_of(self.pad_interval))
        {
            padding_len = pick(
                self.namespaces
                    .prf32(LABEL_PAYLOAD_PAD, seq, payload_len as u32),
                self.pad_min,
                self.pad_max,
            );
        }
        let payload_tag_len = if payload_len > 0 { TAG_LEN } else { 0 };
        let frame_len = total_len
            + prefix_len
            + HEADER_CIPHER_LEN
            + padding_len
            + payload_len
            + payload_tag_len;
        let target_len = self.write_target(seq, frame_len);
        if target_len > frame_len {
            padding_len += (target_len - frame_len).min(MAX_EXTRA_PADDING);
        }
        if total_len > 0 {
            padding_len = self.first_record_padding_len(
                padding_len,
                prefix_len,
                salt_prefix_len,
                payload_len,
            );
        }
        padding_len.min(0xffff)
    }

    fn write_target(&self, seq: u32, frame_len: usize) -> usize {
        if frame_len > 0x05b3 {
            return if frame_len <= 0xffff {
                frame_len
            } else {
                0xffff
            };
        }
        let mut target_len = if (seq as usize) < self.write_first {
            self.write_seq[seq as usize]
        } else {
            let index = self
                .namespaces
                .prf32(LABEL_WRITE_TARGET, seq, frame_len as u32) as usize
                % self.write_buckets.len();
            self.write_buckets[index]
        };
        if self.write_policy == 2 {
            let raw = self.namespaces.prf32(LABEL_WRITE_JITTER_V, seq, 0);
            let span = (self.write_jitter as u32).wrapping_mul(2).wrapping_add(1);
            let jitter = (raw % span) as isize - self.write_jitter as isize;
            target_len = (target_len as isize + jitter).max(1) as usize;
        }
        let spread = MAX_EXTRA_PADDING
            .min(((frame_len as u64) * (self.write_jitter_pct as u64) / 100) as usize);
        if self
            .namespaces
            .prf32(LABEL_WRITE_TARGET, seq, spread as u32)
            & 1
            == 0
        {
            if target_len + spread <= 0xffff {
                target_len += spread;
            } else {
                target_len = 0xffff;
            }
        } else {
            let half_spread = spread >> 1;
            if target_len > half_spread {
                target_len -= half_spread;
            }
        }
        while frame_len > target_len {
            let index = self
                .namespaces
                .prf32(LABEL_WRITE_NEXT, seq, target_len as u32) as usize
                % self.write_buckets.len();
            let mut next_len = self.write_buckets[index];
            if next_len <= target_len {
                next_len = target_len + self.pad_max;
                if next_len > 0xffff {
                    return 0xffff;
                }
            }
            target_len = next_len;
        }
        target_len
    }

    fn first_record_padding_len(
        &self,
        padding_len: usize,
        prefix_len: usize,
        salt_prefix_len: usize,
        payload_len: usize,
    ) -> usize {
        let overhead_len = salt_prefix_len + prefix_len + padding_len;
        let threshold_input = payload_len + if payload_len == 0 { 0x27 } else { 0x37 };
        let threshold = (threshold_input * 25).div_ceil(75).max(0xc0);
        if overhead_len >= threshold {
            return padding_len;
        }
        let mut target_padding_len = threshold.saturating_sub(salt_prefix_len + prefix_len);
        let max_padding_len = self.pad_max + MAX_EXTRA_PADDING;
        if max_padding_len <= target_padding_len {
            target_padding_len = max_padding_len;
        }
        if target_padding_len > 0xfffe {
            return padding_len;
        }
        target_padding_len
    }

    /// 按 generator 生成 padding/prefix/salt block 的填充字节。
    fn fill_padding(&self, seq: u32, output: &mut [u8]) {
        if output.is_empty() {
            return;
        }
        self.namespaces.prf_bytes(LABEL_PADDING, seq, output);
        match self.generator {
            0 => {
                let bit_count = pick_u32(
                    self.namespaces.prf32(LABEL_BIT_PERCENT, seq, 0),
                    self.bit_min,
                    self.bit_max,
                );
                let mut rotate = 1usize;
                let scaled = bit_count as usize * 8;
                if scaled > 0x31 {
                    rotate = 7;
                    if scaled <= 0x02ed {
                        rotate = (scaled + 0x32) / 100;
                    }
                }
                let table_row = rotate.max(1);
                for (index, value) in output.iter_mut().enumerate() {
                    let old = *value;
                    let raw = old.wrapping_add(index as u8);
                    let table_value =
                        BIT_ROTATE_TABLE[table_row * 16 + usize::from((raw ^ old) & 0x0f)];
                    let rotation = usize::from((raw ^ (old >> 4)) & 7);
                    *value = table_value.rotate_left(rotation as u32);
                }
            }
            1 => {
                let total = self.g1 + self.g2 + self.g3;
                for (index, value) in output.iter_mut().enumerate() {
                    let bucket = usize::from(*value) % total;
                    let raw = if bucket < self.g1 {
                        (*value).wrapping_add(index as u8)
                    } else if bucket < self.g1 + self.g2 {
                        *value ^ (index as u8)
                    } else {
                        (*value).wrapping_add((index as u8).wrapping_mul(7))
                    };
                    *value = if bucket < self.g1 {
                        pick(u32::from(raw), 0x20, 0x7e) as u8
                    } else if bucket < self.g1 + self.g2 {
                        pick(u32::from(raw), 0x80, 0xbf) as u8
                    } else {
                        pick(u32::from(raw), 0xc0, 0xff) as u8
                    };
                }
            }
            2 => {
                for (index, value) in output.iter_mut().enumerate() {
                    let low = (usize::from(*value & 0x0f) + self.g4 + (index & 1)) % 10;
                    let high = (usize::from(*value) + ((index & 3) << 4) + 0x30) & 0xf0;
                    *value = (high | low) as u8;
                }
            }
            _ => {
                let mut motif = [0u8; 32];
                self.namespaces.prf_bytes(LABEL_MOTIF, seq, &mut motif);
                let motif_len = if self.g5 * 4 == 0 { 4 } else { self.g5 * 4 };
                let period = self.g6.max(5);
                let mut block_offset = 0;
                let mut motif_offset = 0;
                for (index, value) in output.iter_mut().enumerate() {
                    if block_offset < period - 3 {
                        *value =
                            ((self.g5 + 3) as u8).wrapping_mul(index as u8) ^ motif[motif_offset];
                    } else if block_offset < period - 1 {
                        *value = 0x30 | (*value % 10);
                    }
                    block_offset += 1;
                    if block_offset == period {
                        block_offset = 0;
                    }
                    motif_offset += 1;
                    if motif_offset == motif_len {
                        motif_offset = 0;
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // salt block 的置换与掩码
    // -----------------------------------------------------------------------

    fn salt_shuffle_prf(ns_salt: u64, domain: u32, index: u32) -> u32 {
        let rdx = u64::from(index).wrapping_mul(COEF_B).wrapping_add(ADD_B);
        let rdi = ns_salt ^ SALT_NS_XOR;
        let rsi = u64::from(domain).wrapping_mul(COEF_A).wrapping_add(ADD_A);
        let y = splitmix64(rdx ^ rdi ^ rsi);
        (y ^ (y >> 32)) as u32
    }

    fn shuffle_perm(ns_salt: u64, rounds: u8, length: usize) -> Vec<usize> {
        let mut out: Vec<usize> = (0..length).collect();
        if length == 0 {
            return out;
        }
        for round in 0..u32::from(rounds.max(1)) {
            let domain = MIX_HANDSHAKE_DOMAIN.wrapping_add(round);
            for index in 0..length {
                let span = (length - index) as u64;
                let raw = u64::from(Self::salt_shuffle_prf(ns_salt, domain, index as u32));
                let swap_index = index + (raw % span) as usize;
                out.swap(index, swap_index);
            }
        }
        out
    }

    fn salt_mask(ns_salt: u64, mix_stride: usize, index: u32) -> u8 {
        let prf = prf_fold(
            ns_salt,
            LABEL_MOTIF,
            u64::from(MIX_HANDSHAKE_DOMAIN),
            u64::from(index),
        );
        (index as u8).wrapping_mul(mix_stride as u8) ^ (prf as u8)
    }

    /// 从线上的 salt block 还原 16 字节 AEAD salt。
    pub(crate) fn extract_salt(&self, block: &[u8]) -> [u8; SALT_LEN] {
        let perm = Self::shuffle_perm(
            self.namespaces.salt,
            self.mix_rounds_handshake as u8,
            block.len(),
        );
        let mut salt = [0u8; SALT_LEN];
        for (index, byte) in salt.iter_mut().enumerate() {
            *byte = Self::salt_mask(
                self.namespaces.salt,
                self.mix_stride_handshake,
                index as u32,
            ) ^ block[perm[index]];
        }
        salt
    }

    /// 把 AEAD salt 写入已经预填充的 salt block。
    pub(crate) fn write_salt_block(&self, salt: &[u8; SALT_LEN], block: &mut [u8]) {
        debug_assert_eq!(block.len(), self.salt_block_len);
        let perm = Self::shuffle_perm(
            self.namespaces.salt,
            self.mix_rounds_handshake as u8,
            block.len(),
        );
        for (index, byte) in salt.iter().enumerate() {
            block[perm[index]] = Self::salt_mask(
                self.namespaces.salt,
                self.mix_stride_handshake,
                index as u32,
            ) ^ byte;
        }
    }

    // -----------------------------------------------------------------------
    // padding 与 payload 的混合
    // -----------------------------------------------------------------------

    /// writer 混合、reader 逆混合。两者使用完全相同的置换。
    pub(crate) fn mix_padding_payload(
        &self,
        seq: u32,
        padding: &mut [u8],
        payload_cipher: &mut [u8],
    ) {
        let n = padding.len().min(payload_cipher.len());
        if n == 0 {
            return;
        }
        for round in 0..self.mix_rounds {
            match self.mix_mode {
                0 => {
                    let stride = (self.mix_stride + (round % 3) as usize).max(1);
                    if stride == 1 {
                        for index in 0..n {
                            std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
                        }
                    } else {
                        let mut offset = self.mix_offset_base % stride;
                        while offset < n {
                            std::mem::swap(&mut padding[offset], &mut payload_cipher[offset]);
                            offset += stride;
                        }
                    }
                }
                1 => {
                    let block = self.mix_block;
                    let mut offset = (round as usize & 1) * block;
                    while offset + block <= n {
                        for index in offset..offset + block {
                            std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
                        }
                        offset += block * 2;
                    }
                }
                _ => {
                    let stride = (self.mix_stride + (round % 3) as usize).max(1);
                    if stride == 1 {
                        for index in 0..n {
                            std::mem::swap(&mut padding[index], &mut payload_cipher[index]);
                        }
                    } else {
                        let raw = self.namespaces.prf32(LABEL_MIX_OFFSET, seq, round);
                        let mut offset = ((u64::from(raw) + self.mix_offset_base as u64)
                            % stride as u64) as usize;
                        while offset < n {
                            std::mem::swap(&mut padding[offset], &mut payload_cipher[offset]);
                            offset += stride;
                        }
                    }
                }
            }
        }
    }
}

/// `BLAKE2b-256(profileSeed || psk)`。
fn profile_secret(psk: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(PROFILE_SEED);
    hasher.update(psk);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// AEAD / nonce
// ---------------------------------------------------------------------------

const KDF_MEMORY_KIB: u32 = 8;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;
const KDF_OUTPUT_LEN: usize = 32;
const AES_KEY_LEN: usize = 16;

fn derive_key(psk: &[u8], salt: &[u8; SALT_LEN]) -> io::Result<[u8; AES_KEY_LEN]> {
    let params = Params::new(
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        Some(KDF_OUTPUT_LEN),
    )
    .map_err(|_| internal_error())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; KDF_OUTPUT_LEN];
    argon
        .hash_password_into(psk, salt, &mut output)
        .map_err(|_| internal_error())?;
    let mut key = [0u8; AES_KEY_LEN];
    key.copy_from_slice(&output[..AES_KEY_LEN]);
    Ok(key)
}

fn new_cipher(psk: &[u8], salt: &[u8; SALT_LEN]) -> io::Result<Aes128Gcm> {
    let key = derive_key(psk, salt)?;
    Aes128Gcm::new_from_slice(&key).map_err(|_| internal_error())
}

fn increase_nonce(nonce: &mut [u8; NONCE_LEN]) -> io::Result<()> {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return Ok(());
        }
    }
    Err(io::Error::other("Snell v6 nonce 溢出"))
}

fn put_header(header: &mut [u8; HEADER_PLAIN_LEN], padding_len: usize, payload_len: usize) {
    header[0] = HEADER_VERSION;
    header[1] = 0;
    header[2] = 0;
    header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
}

fn parse_header(header: &[u8]) -> io::Result<(usize, usize)> {
    let header: [u8; HEADER_PLAIN_LEN] = header
        .try_into()
        .map_err(|_| invalid("Snell v6 记录头长度无效"))?;
    if header[0] != HEADER_VERSION {
        return Err(invalid("Snell v6 记录头版本无效"));
    }
    // shaped 读取端与上游一致：忽略两个保留字节。
    let padding_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let payload_len = usize::from(u16::from_be_bytes([header[5], header[6]]));
    Ok((padding_len, payload_len))
}

// ---------------------------------------------------------------------------
// 写入端
// ---------------------------------------------------------------------------

/// default-mode 记录写入端。
///
/// 记录级 API 是同步的，便于在不同运行时的异步记录层中复用：
///
/// * [`ShapedWriter::write_data_at`] 对应上游 `Write`（按 chunk 策略切分）。
/// * [`ShapedWriter::write_packet_at`] 对应 `WritePacketBuffer`（整包一个记录，
///   但仍推进 chunk 状态）。
/// * [`ShapedWriter::write_zero_chunk_at`] 对应 `WriteZeroChunk`。
pub(crate) struct ShapedWriter {
    profile: Profile,
    cipher: Aes128Gcm,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    seq: u32,
    salt_sent: bool,
    chunk_size: usize,
    last_write_unix: i64,
}

impl ShapedWriter {
    /// 使用调用方提供的 16 字节 salt 创建写入端（测试或外部 CSPRNG）。
    pub(crate) fn new(psk: &[u8], salt: [u8; SALT_LEN]) -> io::Result<Self> {
        Self::with_profile(Profile::new(psk), psk, salt)
    }

    /// 与 [`Self::new`] 相同，但复用已派生的 profile。
    pub(crate) fn with_profile(
        profile: Profile,
        psk: &[u8],
        salt: [u8; SALT_LEN],
    ) -> io::Result<Self> {
        let cipher = new_cipher(psk, &salt)?;
        Ok(Self {
            profile,
            cipher,
            salt,
            nonce: [0u8; NONCE_LEN],
            seq: 0,
            salt_sent: false,
            chunk_size: 0,
            last_write_unix: 0,
        })
    }

    /// 使用系统 CSPRNG 生成 salt。
    pub(crate) fn new_random(psk: &[u8]) -> io::Result<Self> {
        Self::new(psk, random_salt()?)
    }

    pub(crate) fn profile(&self) -> &Profile {
        &self.profile
    }

    pub(crate) fn salt(&self) -> [u8; SALT_LEN] {
        self.salt
    }

    pub(crate) fn seq(&self) -> u32 {
        self.seq
    }

    /// 当前时间（秒）写入。
    pub(crate) fn write_data(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        self.write_data_at(data, unix_now())
    }

    /// 按上游 `Write` 的 chunk/write 策略切分并编码。
    pub(crate) fn write_data_at(&mut self, mut data: &[u8], now_unix: i64) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        while !data.is_empty() {
            let limit = self.payload_limit_for(now_unix)?;
            let count = data.len().min(limit);
            output.extend_from_slice(&self.make_record(&data[..count])?);
            data = &data[count..];
        }
        Ok(output)
    }

    /// UDP 包模式：推进 chunk 状态后，把整包编码为单个记录。
    pub(crate) fn write_packet_at(&mut self, payload: &[u8], now_unix: i64) -> io::Result<Vec<u8>> {
        if payload.len() > MAX_PAYLOAD {
            return Err(invalid("Snell v6 payload 超过记录上限"));
        }
        if payload.is_empty() {
            return Ok(Vec::new());
        }
        self.payload_limit_for(now_unix)?;
        self.make_record(payload)
    }

    pub(crate) fn write_zero_chunk(&mut self) -> io::Result<Vec<u8>> {
        self.write_zero_chunk_at(unix_now())
    }

    /// 编码零块（逻辑流 EOF）。零块仍可携带 shaped padding。
    pub(crate) fn write_zero_chunk_at(&mut self, now_unix: i64) -> io::Result<Vec<u8>> {
        self.payload_limit_for(now_unix)?;
        self.make_record(&[])
    }

    fn payload_limit_for(&mut self, now_unix: i64) -> io::Result<usize> {
        if self.last_write_unix == 0
            || now_unix.saturating_sub(self.last_write_unix) > self.profile.idle_reset_sec
        {
            self.chunk_size = self.profile.chunk_initial;
        }
        if self.chunk_size == 0 {
            self.chunk_size = self.profile.chunk_initial;
        }
        let mut payload_limit = self.profile.chunk_payload_limit(self.seq, self.chunk_size);
        if self.seq == 0 {
            payload_limit = payload_limit.min(self.profile.first_record_cap);
        }
        self.chunk_size = self.profile.next_chunk_size(self.chunk_size);
        self.last_write_unix = now_unix;
        Ok(payload_limit.clamp(1, MAX_PAYLOAD))
    }

    /// 生成单个记录（不改变 chunk 状态，但会推进 seq/nonce/salt 状态）。
    fn make_record(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        if payload.len() > MAX_PAYLOAD {
            return Err(invalid("Snell v6 payload 超过记录上限"));
        }
        let seq = self.seq;
        let prefix_len = self.profile.record_prefix_len(seq);
        let (salt_block_len, salt_prefix_len) = if self.salt_sent {
            (0, 0)
        } else {
            let salt_block_len = self.profile.salt_block_len;
            (salt_block_len, salt_block_len - SALT_LEN)
        };
        let padding_len = self.profile.padding_len(
            seq,
            payload.len(),
            prefix_len,
            salt_prefix_len,
            salt_block_len,
        );
        let payload_cipher_len = if payload.is_empty() {
            0
        } else {
            payload.len() + TAG_LEN
        };
        let mut output = Vec::with_capacity(
            salt_block_len + prefix_len + HEADER_CIPHER_LEN + padding_len + payload_cipher_len,
        );

        // 首记录：先按 sentinel seq 填充，再写入被置换/掩码的 salt。
        if salt_block_len > 0 {
            let mut block = vec![0u8; salt_block_len];
            self.profile.fill_padding(u32::MAX, &mut block);
            self.profile.write_salt_block(&self.salt, &mut block);
            output.extend_from_slice(&block);
            self.salt_sent = true;
        }

        // record prefix 同时作为加密头的 AAD。
        let mut prefix = vec![0u8; prefix_len];
        self.profile.fill_padding(seq, &mut prefix);
        output.extend_from_slice(&prefix);

        let mut header = [0u8; HEADER_PLAIN_LEN];
        put_header(&mut header, padding_len, payload.len());
        let header_cipher = self
            .cipher
            .encrypt(
                (&self.nonce).into(),
                Payload {
                    msg: &header,
                    aad: &prefix,
                },
            )
            .map_err(|_| internal_error())?;
        increase_nonce(&mut self.nonce)?;
        output.extend_from_slice(&header_cipher);

        // padding 先填充，然后作为 payload 的 AAD；最后与密文混合。
        let mut padding = vec![0u8; padding_len];
        self.profile.fill_padding(seq, &mut padding);
        if !payload.is_empty() {
            let mut payload_cipher = self
                .cipher
                .encrypt(
                    (&self.nonce).into(),
                    Payload {
                        msg: payload,
                        aad: &padding,
                    },
                )
                .map_err(|_| internal_error())?;
            increase_nonce(&mut self.nonce)?;
            self.profile
                .mix_padding_payload(seq, &mut padding, &mut payload_cipher);
            output.extend_from_slice(&padding);
            output.extend_from_slice(&payload_cipher);
        } else {
            output.extend_from_slice(&padding);
        }

        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| io::Error::other("Snell v6 seq 溢出"))?;
        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// 读取端
// ---------------------------------------------------------------------------

/// 解码结果。`Zero` 对应上游的 `io.EOF` 零块。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DecodedRecord {
    Data(Vec<u8>),
    Zero,
}

struct PendingRecord {
    padding_len: usize,
    payload_len: usize,
    seq: u32,
}

/// default-mode 增量读取端。
///
/// 调用方把 socket/缓冲区读到的字节交给 [`Self::push`]，然后反复调用
/// [`Self::next_record`]：`Ok(None)` 表示当前缓冲不足，需继续 `push`。
/// 只在完整记录到齐后才消费状态，可安全用于 `select!` 驱动的读取循环。
pub(crate) struct ShapedReader {
    profile: Profile,
    psk: Vec<u8>,
    cipher: Option<Aes128Gcm>,
    nonce: [u8; NONCE_LEN],
    seq: u32,
    buffer: Vec<u8>,
    offset: usize,
    pending: Option<PendingRecord>,
}

impl ShapedReader {
    pub(crate) fn new(psk: &[u8]) -> Self {
        Self::with_profile(Profile::new(psk), psk)
    }

    pub(crate) fn with_profile(profile: Profile, psk: &[u8]) -> Self {
        Self {
            profile,
            psk: psk.to_vec(),
            cipher: None,
            nonce: [0u8; NONCE_LEN],
            seq: 0,
            buffer: Vec::new(),
            offset: 0,
            pending: None,
        }
    }

    pub(crate) fn profile(&self) -> &Profile {
        &self.profile
    }

    pub(crate) fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// 尚未消费的缓冲字节数。
    pub(crate) fn buffered(&self) -> usize {
        self.buffer.len() - self.offset
    }

    /// 尝试解码下一条记录；缓冲不足时返回 `Ok(None)`。
    pub(crate) fn next_record(&mut self) -> io::Result<Option<DecodedRecord>> {
        loop {
            if let Some(pending) = self.pending.as_ref() {
                let body_len = pending.padding_len
                    + pending.payload_len
                    + if pending.payload_len > 0 { TAG_LEN } else { 0 };
                if self.available() < body_len {
                    self.compact();
                    return Ok(None);
                }
                let padding_len = pending.padding_len;
                let payload_len = pending.payload_len;
                let seq = pending.seq;
                if payload_len == 0 {
                    let _ = self.take(padding_len);
                    self.pending = None;
                    self.compact();
                    return Ok(Some(DecodedRecord::Zero));
                }
                let mut padding = self.take(padding_len).to_vec();
                let mut payload_cipher = self.take(payload_len + TAG_LEN).to_vec();
                self.profile
                    .mix_padding_payload(seq, &mut padding, &mut payload_cipher);
                let cipher = self
                    .cipher
                    .as_ref()
                    .ok_or_else(|| io::Error::other("Snell v6 AEAD 未初始化"))?;
                let payload = cipher
                    .decrypt(
                        (&self.nonce).into(),
                        Payload {
                            msg: &payload_cipher,
                            aad: &padding,
                        },
                    )
                    .map_err(|_| auth_error())?;
                increase_nonce(&mut self.nonce)?;
                if payload.len() != payload_len {
                    return Err(auth_error());
                }
                self.pending = None;
                self.compact();
                return Ok(Some(DecodedRecord::Data(payload)));
            }

            if self.cipher.is_none() {
                let block_len = self.profile.salt_block_len;
                if self.available() < block_len {
                    self.compact();
                    return Ok(None);
                }
                let block = self.take(block_len).to_vec();
                let salt = self.profile.extract_salt(&block);
                self.cipher = Some(new_cipher(&self.psk, &salt)?);
                continue;
            }

            let prefix_len = self.profile.record_prefix_len(self.seq);
            let header_total = prefix_len + HEADER_CIPHER_LEN;
            if self.available() < header_total {
                self.compact();
                return Ok(None);
            }
            let prefix = self.take(prefix_len).to_vec();
            let header_cipher = self.take(HEADER_CIPHER_LEN).to_vec();
            let cipher = self
                .cipher
                .as_ref()
                .ok_or_else(|| io::Error::other("Snell v6 AEAD 未初始化"))?;
            let header = cipher
                .decrypt(
                    (&self.nonce).into(),
                    Payload {
                        msg: &header_cipher,
                        aad: &prefix,
                    },
                )
                .map_err(|_| auth_error())?;
            increase_nonce(&mut self.nonce)?;
            let (padding_len, payload_len) = parse_header(&header)?;
            let seq = self.seq;
            self.seq = self
                .seq
                .checked_add(1)
                .ok_or_else(|| io::Error::other("Snell v6 seq 溢出"))?;
            self.pending = Some(PendingRecord {
                padding_len,
                payload_len,
                seq,
            });
        }
    }

    fn available(&self) -> usize {
        self.buffer.len() - self.offset
    }

    fn take(&mut self, length: usize) -> &[u8] {
        let start = self.offset;
        let end = start + length;
        self.offset = end;
        &self.buffer[start..end]
    }

    fn compact(&mut self) {
        if self.offset == self.buffer.len() {
            self.buffer.clear();
            self.offset = 0;
        } else if self.offset >= 4096 {
            self.buffer.drain(..self.offset);
            self.offset = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// 随机数与工具
// ---------------------------------------------------------------------------

/// 生成首记录 salt。必须使用 CSPRNG。
pub(crate) fn random_salt() -> io::Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut salt)
        .map_err(|_| io::Error::other("Snell v6 安全随机源失败"))?;
    Ok(salt)
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn auth_error() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "Snell v6 认证失败")
}

fn internal_error() -> io::Error {
    io::Error::other("Snell v6 内部错误")
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const PSK: &[u8] = b"0123456789ab";
    const SALT: [u8; SALT_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    // 由独立的 Python 参考实现生成（非本 crate 代码运行所得）。
    const RECORD_HELLO_HEX: &str = "3c8b996cf0c5c32e1e1ee4c51e6cccc5874799b18777c3c51e8766c6788d395c1ed1cce83c63cc3c3c8efb6c1e3672f0c33c3909e80ff0c13c6c931be1a3335ce1e233c61e78e1a3f0c8721ef06c3f74e83cc3877878e4a35647d73cf0749ce2f0d133b1788d278ec38b2ee13cd127d6e12e4c637878e47978d17a6c0fc666f0c38799f03cd81fb13c1d9c870f8d335ce33d971f2fe3c79eec9ef1f1bc37ec9be3a73b737c3e1fe3d99ec73797375ed31f7ab37c3ef1e5f49de9e5e3bcf11f6ec7e69db91f1fc7e9d97cc71fbce33b733e4f3b7cf2e31ff1673de31f7c73cb3d7cf8f1f8e31f7cd3ecb97cf8e51fecb93e3dec7cf2f88f3e9d7ac73e7c373bf1f17abcfadd022f70e359460dcc146effeeb058fc2962584e751078d3573ec7c7cd7c671679b5798fbcdc3e7e53d88f8fcbf4ece9f13ef19b7c738fdc9df1f27c1ff13b3d3ee3f18f9d9ec7e97ce3f8f88ff876c7f87c2f373b6e8f7a97cde3dce5a79d3d3ef8e51fece3f8b98f1fbcf8e3d3ce8ff8e3f28f2fe93ea7e56e8ff8f89ece8f8ff1bc7cce7cf83de5372f6ec7f46773c7e3cb6e8fd33e1f8f375ef8cbe6769be33ee3cde5733e8f3bf1e5e3c7f89d9ef23e3e3ef13d7cb9f1cd2fc75e1fd9f41ff12ff8d97a8ff4bcf1cb3ec77a674fe3f88fe3f1d3e39b7cc7973ebc7a677c8f7cf8e379f4e3cdce7c8f3e1f4fce4fe3f82f7cbca78fd376c7f1e37cc7d98f7c7c97733ef8f1e9ec8f979bf13eb39ef83e2fe32f6ef89e9d8f1fc71f6e3bf85e1f5e6e799b3e6ee33e8fe3f1f1769e3ef18fdc9d37f84f5e6e8f1ff1e39df47c8ff8f1f8e68fcdf8e65e3ee3d3ec6e97e379f1d9cdc737f1c797cdf1f4674f3e73e51f3b738f7ae37ce53e7c4f67a7c7e3e3f8ce8fe34f5e7cf17c799e3bd37c3e5ee6f18f1f73671f5ef13e9e9d1f8fe3c73e3bdcf89b1fe62fc73e7a671fcbf17c7c9d9ec737b33ecb3ee34f9d9b1fdccb8f767ac7d3f8c71f3ec7dcb3e3973ee5e3cef43e3db36e1f1f7cf176e38f8f3e6e769b1fdccb1f797cf8d3cef85e8f5eb93ef4f1b997c7bcc73ee9ce7a8f1f1ff1bc7af83dcef18f8f1f7cd9dc7c6e2fc7ec9e3e6e9d9b7c7c971f3bdcc7c71f7cece91ff4bc1f1f3e8fa7ecd3f27c7c7cece37c7c7ccd3ec7f2e9cee3e5c7e3cd9d7ae3d31f8fe5e61f3e678fc77cbc3ef8a7f16eb38fc78f1fd3679e1fc77c3ef1373ee6ece61ff81f7a9d8fe38f97cd979e1f73f8cd971f8f4f678fe53e3e7ce537c7cd1fe33ef8f19ece1fc71f1f3ee337e3e65ef8f11fc7f8b3e3f8c75ee376e93ea79d7c79f8f8f19d9ef8f8e337b39bc73dcbf1f2e33e7cb39e8f1f3e1fcb7a3ee99d7ce3e3f13dd9e9f1c7bc7cf1c73e9ee36e977cf8a767d33e7c7cb9d9dcf84f7ccd97f8e5d33bd37c8fe5e6f14fc76e9d9b2ff8c7e69df479f1f2f87c3e1f9e1f3e7cf83ea7d9e63e6ef19bcba7f8a7ec73f2e3f1d3ce3e1ff87c7379a71fa797f82ff8cb9e76f8f273e573ec8ff19bcbf83e8fc7f1ec3d3e8f1f8ff2f4e3e93bc7c7f18f3d67a78ff8f29b5ed3c7e99d8ff27cf1f13b3ee3e3f18fe3e6c7b9671fcb1ff88fce3de51f8ff879377c372ff8797c79f8d9d3973e8ff167e9f8e679f8c7f1f1f1677af8dce57cf87af1e9f237cbf87ca7d93df88fe5cdd9e6f13dd97cc7f1c7a79d9bc7cdf1c767f87c3ec737f8c7f17aecd3bc7c3ef88f6ec7e98f3e8ff8f1f4ce7a3ec7e5375ee3c7c79d37c77c5e9e9da7f1c7cb1fd9733ef41fc7cb7ccba7ecd38f7cbcf1bcb97cdc67c7bc3ecb4fb3f12f1f1fcd76dc3ec7d9f8c7c7f14fce9e7cf8cb3e5edcf8a73b3ec7f13e4f9d1ff8e3977cce4f1fa7676ee33e798fcef4bc3e5e8f8f3d1f9eb3f8791fe33eb3c7c71f7c1fcbd37c1fd91fe3f83e7ab31fc73ecbf1ce3ef8732f8f7c73e3d3d99e8f3e3e9b797ac7b95ef87c6ef17c9d3df8e38fc7c79be3e9676e3eb9f8e9674f3ee32fc7ce6e8f7af83ee53e97e9b39e97f88f8fb3f4c74f3e07bcfb56cf1f9b3f3d6b8f31e37b720e3d8f7c92";
    const ZERO_CHUNK_HEX: &str = "3c8b996cf0c5c32e1e1ee4c51e6cccc5874799b18777c3c51e8766c6788d395c1ed1cce83c63cc3c3c8efb6c1e3672f0c33c3909e80ff0c13c6c931be1a3335ce1e233c61e78e1a3f0c8721ef06c3f74e83cc3877878e4a35647d73cf0749ce2f0d133b1788d278ec38b2ee13cd127d6e12e4c637878e47978d17a6c0fc666f0c38799f03cd81fb13c1d9c870f8d335ce33d971f2fe3c79eec9ef1f1bc37ec9be3a73b737c3e1fe3d99ec73797375ed31f7ab37c3ef1e5f49de9e5e3bcf11f6ec7e69db91f1fc7e9d97cc71fbce33b733e4f3b7cf2e31ff1673de31f7c73cb3d7cf8f1f8e31f7cd3ecb97cf8e51fecb93e3dec7cf2f88f3e9d7ac73e7c373bf1f17abcfadd022889e35c846b61fba057b09fedd4ab5f356de8c7f86ecee3e58fc7f4d93d976ebcc7f1b97c4fd97c5ef1e3a7b3f8798fc78f8f9e1fd397c7bce3f1c7d94ff11fc77c679e7c3d3bc7e3e3e33d679e797c8f1f5e9e3e4fd9c7bce38f4f9df4c7cdc7c7f81fc7e9b36e973ecb7ab39ecbf18fc7768f7c7c9d7ccb1fe34f3bd37c7cf23ed9d38f3de5e3f1f12fe63b37e31f5ef1c7b9f14fece37973c77cb3d31f8fbcf8ece67ce98f3ecb7c977a3b9ef8e3cbb95e3df16e7cf85ee33e9eec7cf8f15ef1ec73f8a73e7c1f7c8f8fb38f8ff88ff82fdcf83dcedc8f8ff8e93bf8e36ef2373e733ea7b31ff83ef8e93b737cf18ff1f19ec7dcf2f8e51f7c7c9d7cf1f1f2e38f9ef1f4f18f7cf1f8e9b34f8f1f3e8f1fe6e33e76f88fdcf2c79d9b3e6e3e9bec9bf8e3f173f28fc7f49de9f8e37cf86737f1d3b3f8e3e38f8fece3f87cbcf1b3d33e9b76f8791ff2f43bcdcbe3f1e3cea71fcd9de3e31f8f8f3bf179c78fe6ecdcf8d367b9f8e6e3cdec3e7c7cf28ff2f4e3f4ece68f3ec7d3d9f83ee3971f8fe98f3de3cdc77c796ecec797f83ee35eb9c7a7ec8f2fe31f1f9df1f8f87c1fb34fe3e6673e7ce33e1feca71fe3f8f88f6e1f3df173f11ff23ed9e33e8ff8f13b73c79e3be38f1f7ce9cef4f83e8f9bb3dc1f3dcb1f7c7c7cd3cea7e38fe51fb33e1fdcce7cc79be33d763d7c7c5ecdf24f3e73d937c7c77c3dd96e2ff15e1fc737f19bb33e3eb9f8c7ece33e3ebce3794ff83ee3dc2fc71ff8679ec78ff1cdec6e8f3ec7f82f3ec7c7cee33e7ce3f1cef4e39e5e9be51f79a7b3e38fe3f27c767a1ff42ff8e33ef8f49d7af13ef1c7bce6f8732fe6e5c7e3e63be97c3e7c1f76377ca7ec377ce37c8f9d7a1fc7f8f8e3731f735e37f2c7f18f9d3d1fcd973ecb7a3e3d9d1fe3f81f3d9d8ff81f7ce376e98fcde36e97e3e59ed9e63e1f798f67cdf1f4f8f1f81f7c3dcee6f1c77ccd2f738f9ee36e2ff1f89ed97a3e7cf2cdece6f14f67f1f8f8e33dcec73e1fcbf8f137c7e979e35e1f7c9eb39be3372ff1c7377c73f81f791f7cdc3bf8f1f8e51f3edcc7f4763e3e1f7c7ad9a7f1c7c7dc1f9ee33dbce3f27c1f9eb3cd1fc7bcb91fb97cf1f8c72fc7c7e6b33ec7375ef13b9e8f3776c78f1f2f7a9dd3bcb9f2e3e37af8a78f9b5ec7c77c9df4c7f897c7e39b3e1f1ff83e738f7ace7a3e1f5e1f3be6c7cd3b1f3ef8f2dc3b9e3ef897f89d6ee34f679b1f1f973d67a71f8f7c1f6737e373d91fcbf1c7d3769ecbf83e7cec3dc7379d8ff8f8f1c79d37e5c7bc3ed9e37cb9f1dccbe33ea7761f79";
    const AFTER_ZERO_HELLO_HEX: &str = "0e0b26c11a70c15862c13464c183312c838526c1437086618958831c431970191c1cc48c7070c10e4c0b38236883130b383289076870386198c8340ec1238316833283e01c23070b8938830707074c23381c1cc1a11cc1854c1c1c8368e03416c1190e9134070e8389583864a1649832e04614623b9306c8ff829dd80b7a127bba23f52ef35f67360d868c26770ec807da31b5a10ed0e04daa70a9d00768388338c48c0783438c8670381613e01c1c0dc2266107c1e0c126850e0731e00d070d38983883830e1c7023e04689640e383407312c83383464898c0e58c4e00e8334b026070d70c10e3146c1b00d8c1c0e34853161c13870320d320e0e4c83833807c14c5868381a386216e0c1261c1a0770e04c580e701a0e26850e5886910de0071c890e1c3838e031617064980e68e08316890e0ee01a1c6223c12398e01ac11cc29858e00ec1076216c1587007071c38b013580707e02383161c8c4ce08619c116c48c6883689189850e2398e0a191c185c432d0c1e0c162193816a1c8e038702c310783c10ec81c61c1464c831c0e0738622ce083348cd0c807c1268307e0c1e098c134230e64070b38c886917070867026380791a1e031c283854c0e6823e01c4cc8837068c14c91c1581c701c38e02c262c860ee083984670161a38431c1c0b26e007e0e083d0648319893807383883c458a10e1ce038c11c8c6219680783e0c41c07830d1c346107460e38c11c8683262383e06807e091e08c8338e007078526161c38c1c8c470836443c80e8c3885130e38e00e07c4583819c1700e7086852658380ec170e02370e0071c68830e0e8958830e68384c070e0b268c071c1c586261e0074338381683b04cc13870c12cc438348338e0386438916832d0c11a079858c1831ae00d61e0e034e00783e00e26b0e0c834830e0b0e2ce0071a07701c98e01c0743e0c42c1c3213e038e01c6126160e19d03243231c580d833883c1c1260e68c11a38c40b0e2c68c870c1382c98163838d07038b03838e0831a831c61980be0c1e0c1c12c70c20ee0a1e00db06258683207c1c45883c1621c34381a85892c071c831c3132075886230d8343c16285e0e01a70862cc161c43838e0868c4c85e0831c0e0e3238c1a1911c196861988c6832833226c2070e9832e083e0c8c4c238831a641c851c64c4c18307382c31b083e038c89823830bc41c0ec1708313323838d0c813c81cc83419430e70e026b00d83072338b0c1912619a138c10b8907830e1c0738641cc289323407832c317083c883384c61704631381a830d61131634c10d070e191c610e381cc11a07c41c0e0ee0c1311683460e8370c1c1072670e06486380dc138b0071ce0703470c40b4383e070982c0e2c9838070e34c226160707831cc1071c2c314643c18316892c0d0e861998613861896470e0070ec4b0380e430e89701c8c260e0d38e08331580dc1d038621983584cc86838c15813c1381c1a8c0761c1c2311c0783388362850e38d0c843c27070688c0e1c38611358e023c146388c1c16c13807c1e058891c38461a834c2c07b031c8e0190d0e4c3807640e1c38230e194370707043614c85708c0ee0981cc1611c831a70c1e03170c1e0a11c4cc1c18568e01c83c1649861a1c10de0620e38191c7043c1830bc4581a1cc119a1161c58c407381c1a0b266483834383a1850ec20d64383807c126c88346431c13e081ec83e239c264c48538426c4413e086c87f58a5";

    fn decode_hex(text: &str) -> Vec<u8> {
        assert!(text.len().is_multiple_of(2));
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("十六进制"))
            .collect()
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(DIGITS[usize::from(byte >> 4)] as char);
            out.push(DIGITS[usize::from(byte & 0x0f)] as char);
        }
        out
    }

    fn decode_all(reader: &mut ShapedReader) -> Vec<DecodedRecord> {
        let mut records = Vec::new();
        while let Some(record) = reader.next_record().expect("解码失败") {
            records.push(record);
        }
        records
    }

    #[test]
    fn profile_matches_independent_reference() {
        let profile = Profile::new(PSK);

        // BLAKE2b-256(profileSeed || psk)
        assert_eq!(
            encode_hex(&profile_secret(PSK)),
            "fa41469f206ba99e199f01ccadb224329ca9092375baee80b309fb9bfe5f2e37"
        );

        // namespace 派生
        assert_eq!(profile.namespaces.profile, 0xef0c_4788_5344_9105);
        assert_eq!(profile.namespaces.prefix, 0x0281_7f92_954a_ea64);
        assert_eq!(profile.namespaces.motif, 0x7afc_08cb_311b_829b);
        assert_eq!(profile.namespaces.salt, 0x0462_803f_319a_e2cc);
        assert_eq!(profile.namespaces.mix, 0x2c1b_d366_04a2_92e8);
        assert_eq!(profile.namespaces.chunk, 0xe59d_52a8_0819_64e3);
        assert_eq!(profile.namespaces.write, 0xe671_ce99_cec0_4b50);

        // default-mode 参数
        assert_eq!(profile.generator, 0);
        assert_eq!(profile.pad_min, 115);
        assert_eq!(profile.pad_max, 730);
        assert_eq!(profile.pad_count, 8);
        assert_eq!(profile.pad_interval, 3);
        assert_eq!(profile.small_limit, 503);
        assert_eq!(profile.bit_min, 32);
        assert_eq!(profile.bit_max, 66);
        assert_eq!(profile.prefix_min_record, 78);
        assert_eq!(profile.prefix_max_record, 128);
        assert_eq!(profile.mix_mode, 2);
        assert_eq!(profile.mix_rounds, 3);
        assert_eq!(profile.mix_stride, 3);
        assert_eq!(profile.mix_offset_base, 0);
        assert_eq!(profile.mix_block, 37);
        assert_eq!(profile.chunk_policy, 2);
        assert_eq!(profile.chunk_initial, 1403);
        assert_eq!(profile.first_record_cap, 353);
        assert_eq!(profile.chunk_max, 11362);
        assert_eq!(profile.chunk_step, 2920);
        assert_eq!(profile.chunk_jitter, 93);
        assert_eq!(profile.idle_reset_sec, 83);
        assert_eq!(profile.write_policy, 0);
        assert_eq!(profile.write_first, 6);
        assert_eq!(profile.write_jitter, 34);
        assert_eq!(profile.write_jitter_pct, 29);
        assert_eq!(profile.g1, 62);
        assert_eq!(profile.g2, 49);
        assert_eq!(profile.g3, 33);
        assert_eq!(profile.g4, 3);
        assert_eq!(profile.g5, 1);
        assert_eq!(profile.g6, 12);
        assert_eq!(profile.salt_block_len, 144);
        assert_eq!(profile.mix_stride_handshake, 228);
        assert_eq!(profile.mix_rounds_handshake, 1);
        assert_eq!(
            profile.chunk_buckets,
            [8415, 8175, 11229, 8383, 9678, 7058, 7316, 8571]
        );
        assert_eq!(
            profile.write_buckets,
            [1333, 1071, 446, 1383, 910, 421, 975, 1424]
        );
        assert_eq!(
            profile.write_seq,
            [1288, 1349, 1379, 1281, 1224, 927, 1170, 892]
        );
    }

    #[test]
    fn default_profile_is_shaped_not_empty() {
        let profile = Profile::new(PSK);
        // 这些下界确保存在真实 padding、真实 record prefix、真实 mixing
        // 和真实 salt block，而不是用空 padding/unshaped 冒充 default。
        assert!(profile.pad_min >= 0x18);
        assert!(profile.pad_max >= profile.pad_min);
        assert!(profile.pad_count >= 2);
        assert!(profile.pad_interval >= 2);
        assert!(profile.prefix_min_record >= 0x08);
        assert!(profile.prefix_max_record >= profile.prefix_min_record);
        assert!(profile.salt_block_len >= SALT_LEN + 0x10);
        assert!(profile.mix_rounds >= 1);
        assert!(profile.chunk_max > profile.chunk_initial);
        assert!(profile.first_record_cap <= profile.chunk_initial);
        assert!(Mode::Default.is_implemented());
        assert!(!Mode::Unshaped.is_implemented());
        assert!(!Mode::UnsafeRaw.is_implemented());
    }

    #[test]
    fn padding_and_prefix_match_reference() {
        let profile = Profile::new(PSK);

        assert_eq!(profile.record_prefix_len(0), 115);
        assert_eq!(
            (0..6)
                .map(|seq| profile.record_prefix_len(seq))
                .collect::<Vec<_>>(),
            [115, 114, 98, 128, 79, 123]
        );
        assert_eq!(
            profile.padding_len(
                0,
                5,
                115,
                profile.salt_block_len - SALT_LEN,
                profile.salt_block_len
            ),
            1138
        );

        let mut fill = [0u8; 32];
        profile.fill_padding(0, &mut fill);
        assert_eq!(
            encode_hex(&fill),
            "8fcd677c1f3e3ed33b3e3ef13ecd9d7af86ef2c7e5e3f1e3761ff18f8fcde56e"
        );
        let mut sentinel = [0u8; 32];
        profile.fill_padding(u32::MAX, &mut sentinel);
        assert_eq!(
            encode_hex(&sentinel),
            "3c5c0f78c3789ce8e1f0f02e876c668bf08b786c87e2e447786393f03cc3278d"
        );

        // salt block 的还原与写入必须互逆，且不是直接复制 salt。
        let salt: [u8; SALT_LEN] = std::array::from_fn(|index| index as u8);
        let mut block = vec![0u8; profile.salt_block_len];
        profile.fill_padding(u32::MAX, &mut block);
        profile.write_salt_block(&salt, &mut block);
        assert_eq!(profile.extract_salt(&block), salt);
        assert_ne!(&block[..SALT_LEN], &salt[..]);
    }

    #[test]
    fn record_vector_matches_reference() {
        let expected = decode_hex(RECORD_HELLO_HEX);
        let mut writer = ShapedWriter::new(PSK, SALT).expect("writer");
        let record = writer.make_record(b"hello").expect("encode");
        assert_eq!(record.len(), 1441);
        assert_eq!(record, expected);

        let mut reader = ShapedReader::new(PSK);
        reader.push(&expected);
        assert_eq!(
            decode_all(&mut reader),
            vec![DecodedRecord::Data(b"hello".to_vec())]
        );
        assert_eq!(reader.buffered(), 0);
    }

    #[test]
    fn record_vector_decodes_byte_by_byte() {
        let expected = decode_hex(RECORD_HELLO_HEX);
        let mut reader = ShapedReader::new(PSK);
        let mut decoded = Vec::new();
        for byte in &expected {
            reader.push(&[*byte]);
            while let Some(record) = reader.next_record().expect("解码失败") {
                decoded.push(record);
            }
        }
        assert_eq!(decoded, vec![DecodedRecord::Data(b"hello".to_vec())]);
        assert_eq!(reader.buffered(), 0);
    }

    #[test]
    fn zero_chunk_advances_sequence_and_nonce() {
        let zero_expected = decode_hex(ZERO_CHUNK_HEX);
        let hello_expected = decode_hex(AFTER_ZERO_HELLO_HEX);

        let mut writer = ShapedWriter::new(PSK, SALT).expect("writer");
        let zero = writer.write_zero_chunk_at(777).expect("zero");
        assert_eq!(zero, zero_expected);
        assert_eq!(writer.seq(), 1);
        let hello = writer.make_record(b"hello").expect("hello");
        assert_eq!(hello, hello_expected);
        assert_eq!(writer.seq(), 2);

        let mut wire = zero;
        wire.extend_from_slice(&hello_expected);
        let mut reader = ShapedReader::new(PSK);
        reader.push(&wire);
        assert_eq!(
            decode_all(&mut reader),
            vec![DecodedRecord::Zero, DecodedRecord::Data(b"hello".to_vec())]
        );
    }

    #[test]
    fn write_chunking_matches_reference_payload_boundaries() {
        let profile = Profile::new(PSK);
        let mut writer = ShapedWriter::new(PSK, SALT).expect("writer");

        // 与参考实现一致的两次 payload：首个记录被 first_record_cap 限制。
        let data = b"ABCDEFGHIJ".repeat(60);
        let wire = writer.write_data_at(&data, 1_234_567_890).expect("encode");
        assert_eq!(wire.len(), 2397);

        let mut reader = ShapedReader::new(PSK);
        reader.push(&wire);
        let records = decode_all(&mut reader);
        assert_eq!(records.len(), 2);
        let first_len = match &records[0] {
            DecodedRecord::Data(data) => data.len(),
            DecodedRecord::Zero => panic!("不应为零块"),
        };
        let second_len = match &records[1] {
            DecodedRecord::Data(data) => data.len(),
            DecodedRecord::Zero => panic!("不应为零块"),
        };
        assert_eq!((first_len, second_len), (353, 247));
        assert_eq!(first_len, profile.first_record_cap);

        let mut joined = Vec::new();
        for record in records {
            if let DecodedRecord::Data(data) = record {
                joined.extend_from_slice(&data);
            }
        }
        assert_eq!(joined, data);
    }

    #[test]
    fn writer_reader_roundtrip_multiple_sizes() {
        for payload_len in [0usize, 1, 5, 64, 353, 700, 1403, 4096, 0xffff] {
            let payload: Vec<u8> = (0..payload_len)
                .map(|index| (index as u8).wrapping_mul(31))
                .collect();
            let mut writer = ShapedWriter::new(PSK, SALT).expect("writer");
            let wire = writer.write_data_at(&payload, 1000).expect("encode");
            if payload.is_empty() {
                assert!(wire.is_empty());
                continue;
            }
            let mut reader = ShapedReader::new(PSK);
            reader.push(&wire);
            let records = decode_all(&mut reader);
            let mut joined = Vec::new();
            for record in records {
                match record {
                    DecodedRecord::Data(data) => joined.extend_from_slice(&data),
                    DecodedRecord::Zero => panic!("不应为零块"),
                }
            }
            assert_eq!(joined, payload, "payload_len={payload_len}");
        }
    }

    #[test]
    fn zero_chunk_roundtrip_after_multiple_records() {
        let mut writer = ShapedWriter::new(PSK, SALT).expect("writer");
        let mut wire = writer.write_data_at(b"hello", 1).expect("hello");
        wire.extend_from_slice(&writer.write_data_at(b"world", 2).expect("world"));
        wire.extend_from_slice(&writer.write_zero_chunk_at(3).expect("zero"));

        let mut reader = ShapedReader::new(PSK);
        reader.push(&wire);
        assert_eq!(
            decode_all(&mut reader),
            vec![
                DecodedRecord::Data(b"hello".to_vec()),
                DecodedRecord::Data(b"world".to_vec()),
                DecodedRecord::Zero,
            ]
        );
    }

    #[test]
    fn tampered_record_is_rejected() {
        let mut writer = ShapedWriter::new(PSK, SALT).expect("writer");
        let mut record = writer.make_record(b"hello").expect("encode");
        let last = record.len() - 1;
        record[last] ^= 1;

        let mut reader = ShapedReader::new(PSK);
        reader.push(&record);
        let error = reader.next_record().expect_err("篡改必须失败");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn packet_mode_emits_one_record_and_advances_chunk_state() {
        let mut writer = ShapedWriter::new(PSK, SALT).expect("writer");
        let first = writer.write_packet_at(b"p", 10).expect("packet");
        let second = writer.write_packet_at(b"q", 10).expect("packet");
        assert_eq!(writer.seq(), 2);

        let mut wire = first;
        wire.extend_from_slice(&second);
        let mut reader = ShapedReader::new(PSK);
        reader.push(&wire);
        assert_eq!(
            decode_all(&mut reader),
            vec![
                DecodedRecord::Data(b"p".to_vec()),
                DecodedRecord::Data(b"q".to_vec()),
            ]
        );
    }

    #[test]
    fn mode_names_match_upstream() {
        assert_eq!(Mode::parse("").expect("default"), Mode::Default);
        assert_eq!(Mode::parse("default").expect("default"), Mode::Default);
        assert_eq!(Mode::parse("unshaped").expect("unshaped"), Mode::Unshaped);
        assert_eq!(
            Mode::parse("unsafe-raw").expect("unsafe-raw"),
            Mode::UnsafeRaw
        );
        assert!(Mode::parse("other").is_err());
        assert_eq!(Mode::Default.as_str(), "default");
    }
}
