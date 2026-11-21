//! Hysteria2 gecko obfs 的分片/重组层。
//!
//! 参考 `sing-quic@v0.7.2/hysteria2/gecko.go`：在 salamander 加密之内，对
//! 首字节带 QUIC 长首部位（0x80）的报文拆成 2..=8 个分片，每片可带随机
//! 填充；接收端按 `(来源地址, msgID)` 重组。非长首部报文原样通过。
//!
//! 本模块只处理明文分片帧，不包含 salamander；socket 层先解密再交给这里。
//! 所有状态都有界：条目 TTL 8 秒、全局 4096 条、每来源 8 条。

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

/// 分片帧标志位；与 QUIC 长首部最高位一致，因此只对长首部报文分片。
pub(crate) const FRAGMENT_FLAG: u8 = 0x80;
const HEADER_LEN: usize = 5;
const MIN_CHUNKS: u8 = 2;
const MAX_CHUNKS: u8 = 8;
/// 明文分片帧上限（与上游 `geckoMaxOnWireSize` 一致）。
pub(crate) const MAX_FRAME: usize = 2048;
pub(crate) const DEFAULT_MIN_PACKET_SIZE: usize = 512;
pub(crate) const DEFAULT_MAX_PACKET_SIZE: usize = 1200;
const REASSEMBLY_TTL: Duration = Duration::from_secs(8);
const MAX_REASSEMBLY: usize = 4096;
const MAX_PER_SOURCE: usize = 8;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// 是否需要对明文 QUIC 报文分片。
pub(crate) fn should_fragment(packet: &[u8]) -> bool {
    packet.first().is_some_and(|byte| byte & FRAGMENT_FLAG != 0)
}

/// 把明文报文拆成 2..=8 个分片帧。
///
/// 分片内容按 `chunks` 均分，最后一片承接余数；每片填充使线上长度落在
/// `min..=max`（无法满足时填充为 0）。`message_id` 由调用方单调递增。
pub(crate) fn fragment(
    packet: &[u8],
    min_packet_size: usize,
    max_packet_size: usize,
    message_id: u8,
    salt_len: usize,
    random: &mut dyn FnMut(&mut [u8]),
) -> io::Result<Vec<Vec<u8>>> {
    if packet.is_empty() {
        return Err(invalid("gecko 分片输入为空"));
    }
    if min_packet_size == 0 || max_packet_size < min_packet_size {
        return Err(invalid("gecko 分片长度参数无效"));
    }
    let chunks = usize::from(MIN_CHUNKS)
        + usize::from(random_u8(random)?[0]) % usize::from(MAX_CHUNKS - MIN_CHUNKS + 1);
    let chunk_size = packet.len() / chunks;
    let mut frames = Vec::with_capacity(chunks);
    for index in 0..chunks {
        let start = index * chunk_size;
        let end = if index + 1 == chunks {
            packet.len()
        } else {
            start + chunk_size
        };
        let chunk = &packet[start..end];
        let base = salt_len + HEADER_LEN + chunk.len();
        let low = min_packet_size.max(base);
        let pad_len = if low > max_packet_size {
            0
        } else {
            low - base
                + usize::from(u16::from_be_bytes(random_u16(random)?)) % (max_packet_size - low + 1)
        };
        if HEADER_LEN + pad_len + chunk.len() > MAX_FRAME {
            return Err(invalid("gecko 分片帧过长"));
        }
        let mut frame = vec![0u8; HEADER_LEN + pad_len + chunk.len()];
        frame[0] = FRAGMENT_FLAG;
        frame[1] = message_id;
        frame[2] = ((index as u8) << 4) | (chunks as u8 & 0x0f);
        frame[3..5].copy_from_slice(&(pad_len as u16).to_be_bytes());
        random(&mut frame[HEADER_LEN..HEADER_LEN + pad_len]);
        frame[HEADER_LEN + pad_len..].copy_from_slice(chunk);
        frames.push(frame);
    }
    Ok(frames)
}

fn random_u8(random: &mut dyn FnMut(&mut [u8])) -> io::Result<[u8; 1]> {
    let mut value = [0u8; 1];
    random(&mut value);
    Ok(value)
}

fn random_u16(random: &mut dyn FnMut(&mut [u8])) -> io::Result<[u8; 2]> {
    let mut value = [0u8; 2];
    random(&mut value);
    Ok(value)
}

/// 解密后的分片帧视图。
struct Frame<'a> {
    message_id: u8,
    chunk_index: u8,
    total: u8,
    payload: &'a [u8],
}

fn parse_frame(frame: &[u8]) -> Option<Frame<'_>> {
    if frame.len() < HEADER_LEN || frame[0] & FRAGMENT_FLAG == 0 {
        return None;
    }
    let total = frame[2] & 0x0f;
    let chunk_index = frame[2] >> 4;
    if !(MIN_CHUNKS..=MAX_CHUNKS).contains(&total) || chunk_index >= total {
        return None;
    }
    let pad_len = usize::from(u16::from_be_bytes([frame[3], frame[4]]));
    let start = HEADER_LEN.checked_add(pad_len)?;
    let payload = frame.get(start..)?;
    Some(Frame {
        message_id: frame[1],
        chunk_index,
        total,
        payload,
    })
}

struct Entry {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    deadline: Instant,
}

/// 有界的服务端/客户端重组器；键包含来源地址。
#[derive(Default)]
pub(crate) struct Reassembler {
    entries: HashMap<(SocketAddr, u8), Entry>,
    per_source: HashMap<SocketAddr, usize>,
    last_sweep: Option<Instant>,
}

impl Reassembler {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 喂入一个明文分片帧；返回完整报文时表示完成。
    ///
    /// 非法帧、重复分片、超出上限或来源条目超限都返回 `None`，调用方丢弃。
    pub(crate) fn accept(
        &mut self,
        source: SocketAddr,
        frame: &[u8],
        now: Instant,
    ) -> Option<Vec<u8>> {
        let frame = parse_frame(frame)?;
        self.sweep(now);
        let key = (source, frame.message_id);
        if !self.entries.contains_key(&key) {
            let count = self.per_source.entry(source).or_insert(0);
            if *count >= MAX_PER_SOURCE {
                return None;
            }
            if self.entries.len() >= MAX_REASSEMBLY {
                self.evict_oldest();
            }
            self.entries.insert(
                key,
                Entry {
                    chunks: vec![None; usize::from(frame.total)],
                    received: 0,
                    deadline: now + REASSEMBLY_TTL,
                },
            );
            *self.per_source.get_mut(&source)? += 1;
        }
        let entry = self.entries.get_mut(&key)?;
        if entry.chunks.len() != usize::from(frame.total) {
            return None;
        }
        let slot = entry.chunks.get_mut(usize::from(frame.chunk_index))?;
        if slot.is_some() {
            return None;
        }
        *slot = Some(frame.payload.to_vec());
        entry.received += 1;
        if entry.received < entry.chunks.len() {
            return None;
        }
        let entry = self.entries.remove(&key)?;
        if let Some(count) = self.per_source.get_mut(&source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_source.remove(&source);
            }
        }
        Some(entry.chunks.into_iter().flatten().flatten().collect())
    }

    fn sweep(&mut self, now: Instant) {
        if self
            .last_sweep
            .is_some_and(|last| now.saturating_duration_since(last) < REASSEMBLY_TTL / 2)
        {
            return;
        }
        self.last_sweep = Some(now);
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| now >= entry.deadline)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.drop_entry(key);
        }
    }

    fn evict_oldest(&mut self) {
        let Some(key) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.deadline)
            .map(|(key, _)| *key)
        else {
            return;
        };
        self.drop_entry(key);
    }

    fn drop_entry(&mut self, key: (SocketAddr, u8)) {
        if self.entries.remove(&key).is_some()
            && let Some(count) = self.per_source.get_mut(&key.0)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_source.remove(&key.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic() -> impl FnMut(&mut [u8]) {
        let mut state = 0x1234_5678u32;
        move |buffer: &mut [u8]| {
            for byte in buffer {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 24) as u8;
            }
        }
    }

    fn source(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn fragment_and_reassemble_round_trip() {
        let packet: Vec<u8> = (0..1500).map(|index| index as u8).collect();
        let mut random = deterministic();
        let frames = fragment(&packet, 512, 1200, 7, 8, &mut random).unwrap();
        assert!((2..=8).contains(&frames.len()));
        for frame in &frames {
            assert_eq!(frame[0], FRAGMENT_FLAG);
            assert!(frame.len() <= MAX_FRAME);
            let parsed = parse_frame(frame).expect("帧应可解析");
            assert_eq!(parsed.message_id, 7);
            assert_eq!(parsed.total as usize, frames.len());
        }

        let mut reassembler = Reassembler::new();
        let now = Instant::now();
        let mut output = None;
        for frame in frames.iter().rev() {
            if let Some(packet) = reassembler.accept(source(1), frame, now) {
                output = Some(packet);
            }
        }
        assert_eq!(output.as_deref(), Some(packet.as_slice()));
    }

    #[test]
    fn duplicate_chunk_and_inconsistent_total_are_dropped() {
        let packet: Vec<u8> = (0..300).map(|index| index as u8).collect();
        let mut random = deterministic();
        let frames = fragment(&packet, 512, 1200, 1, 8, &mut random).unwrap();
        let mut reassembler = Reassembler::new();
        let now = Instant::now();
        assert!(reassembler.accept(source(1), &frames[0], now).is_none());
        assert!(
            reassembler.accept(source(1), &frames[0], now).is_none(),
            "重复分片"
        );
        // 伪造 total 不一致的另一帧。
        let mut inconsistent = frames[frames.len() - 1].clone();
        inconsistent[2] = (inconsistent[2] & 0xf0) | 0x0f;
        assert!(reassembler.accept(source(1), &inconsistent, now).is_none());
    }

    #[test]
    fn non_fragment_packets_bypass_and_short_frames_are_rejected() {
        assert!(!should_fragment(b"short-header"));
        assert!(should_fragment(&[0xc0, 0, 0, 0, 1]));
        assert!(parse_frame(b"short").is_none());
        let mut reassembler = Reassembler::new();
        assert!(
            reassembler
                .accept(source(1), b"\x00abc", Instant::now())
                .is_none()
        );
    }

    #[test]
    fn entries_expire_and_per_source_limit_is_enforced() {
        let mut reassembler = Reassembler::new();
        let now = Instant::now();
        let frame = [FRAGMENT_FLAG, 0, 0x20, 0, 0, 1, 2];
        for index in 0..MAX_PER_SOURCE {
            let mut frame = frame;
            frame[1] = index as u8;
            assert!(reassembler.accept(source(1), &frame, now).is_none());
        }
        let mut extra = frame;
        extra[1] = 99;
        assert!(
            reassembler.accept(source(1), &extra, now).is_none(),
            "来源条目上限"
        );

        // 过期后同一 msgID 可以重新开始。
        let later = now + REASSEMBLY_TTL + Duration::from_secs(1);
        let mut frame = frame;
        frame[1] = 0;
        assert!(reassembler.accept(source(1), &frame, later).is_none());
    }
}
