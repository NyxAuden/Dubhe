//! 固定 sing-anytls 的文本方案、MD5 与上行 Waste 整形；不改帧或密码原语。
use md5::{Digest, Md5};
use std::{
    collections::HashMap,
    io,
    sync::{Arc, RwLock},
};

pub(super) const DEFAULT_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
const HEADER: usize = 7;
pub(super) const MAX_FRAME: usize = u16::MAX as usize;
const MAX_SIZE: usize = 256 * 1024;
const MAX_GENERATED: usize = 1024 * 1024;
const MAX_ITEMS: usize = 128;
const MAX_TOTAL_ITEMS: usize = 4096;

#[derive(Clone, Debug)]
enum Item {
    Range(usize, usize),
    Check,
}
#[derive(Debug)]
pub(crate) struct Scheme {
    raw: Arc<str>,
    md5: String,
    stop: u32,
    records: HashMap<u32, Vec<Item>>,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "AnyTLS padding方案无效或超出资源上限",
    )
}
impl Scheme {
    pub(crate) fn parse(raw: &str) -> io::Result<Self> {
        if raw.is_empty() || raw.len() > MAX_FRAME {
            return Err(invalid());
        }
        // 与parseSettings相同：不trim，重复键最后一个覆盖，未知键保留于原文摘要。
        let fields: HashMap<_, _> = raw
            .split('\n')
            .filter_map(|line| line.split_once('='))
            .collect();
        let stop = fields
            .get("stop")
            .ok_or_else(invalid)?
            .parse::<i64>()
            .map_err(|_| invalid())? as u32;
        let mut records = HashMap::new();
        let mut total = 0;
        for (key, value) in fields {
            let Ok(packet) = key.parse::<u32>() else {
                continue;
            };
            if packet.to_string() != key {
                continue;
            }
            let mut items = Vec::new();
            let mut maximum = 0usize;
            for item in value.split(',') {
                if item == "c" {
                    items.push(Item::Check);
                } else if let Some((minimum, maximum_text)) = item.split_once('-') {
                    let (Ok(mut min), Ok(mut max)) =
                        (minimum.parse::<i64>(), maximum_text.parse::<i64>())
                    else {
                        continue;
                    };
                    if min > max {
                        std::mem::swap(&mut min, &mut max);
                    }
                    if min <= 0 || max <= 0 {
                        continue;
                    }
                    if max > MAX_SIZE as i64 {
                        return Err(invalid());
                    }
                    let (min, max) = (min as usize, max as usize);
                    // 无业务时纯Waste分支每段另有7字节头，按最坏分配量计算。
                    maximum = maximum
                        .checked_add(max + (max.div_ceil(MAX_FRAME)) * HEADER)
                        .ok_or_else(invalid)?;
                    if maximum > MAX_GENERATED {
                        return Err(invalid());
                    }
                    items.push(Item::Range(min, max));
                }
                if items.len() > MAX_ITEMS {
                    return Err(invalid());
                }
            }
            total += items.len();
            if total > MAX_TOTAL_ITEMS {
                return Err(invalid());
            }
            if !items.is_empty() {
                records.insert(packet, items);
            }
        }
        if let Some(Item::Range(_, max)) = records.get(&0).and_then(|items| items.first())
            && *max > MAX_FRAME
        {
            return Err(invalid());
        }
        let md5 = md5_text(raw);
        Ok(Self {
            raw: Arc::from(raw),
            md5,
            stop,
            records,
        })
    }
    pub(super) fn raw(&self) -> &str {
        &self.raw
    }
    pub(super) fn md5(&self) -> &str {
        &self.md5
    }
    pub(super) fn handshake_size(&self) -> io::Result<usize> {
        match self.records.get(&0).and_then(|items| items.first()) {
            Some(Item::Range(min, max)) => random_range(*min, *max),
            _ => Ok(0),
        }
    }
}

/// 每出站独立，TCP与UoT共用；快照不跨await持锁，也不跨身份串用方案。
#[derive(Debug)]
pub(crate) struct SharedScheme(RwLock<Arc<Scheme>>);
impl Default for SharedScheme {
    fn default() -> Self {
        Self(RwLock::new(Arc::new(
            Scheme::parse(DEFAULT_SCHEME).expect("固定上游默认方案有效"),
        )))
    }
}
impl SharedScheme {
    pub(super) fn snapshot(&self) -> Arc<Scheme> {
        self.0
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
    pub(super) fn update(&self, raw: &[u8]) -> bool {
        let Ok(raw) = std::str::from_utf8(raw) else {
            return false;
        };
        let Ok(scheme) = Scheme::parse(raw) else {
            return false;
        };
        *self.0.write().unwrap_or_else(|error| error.into_inner()) = Arc::new(scheme);
        true
    }
}

pub(super) fn md5_text(raw: &str) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut text = String::with_capacity(32);
    for byte in Md5::digest(raw.as_bytes()) {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 15)] as char);
    }
    text
}

fn random_range(min: usize, max: usize) -> io::Result<usize> {
    if max <= min {
        return Ok(min);
    }
    let span = (max - min) as u64;
    // 拒绝采样使上界不包含，与crypto/rand.Int相同，不产生模偏差。
    let threshold = span.wrapping_neg() % span;
    loop {
        let mut bytes = [0u8; 8];
        aws_lc_rs::rand::fill(&mut bytes)
            .map_err(|_| io::Error::other("AnyTLS padding随机源失败"))?;
        let value = u64::from_le_bytes(bytes);
        if value >= threshold {
            return Ok(min + (value % span) as usize);
        }
    }
}

#[derive(Default)]
pub(super) struct PaddingState {
    packet: u32,
    stopped: bool,
}
impl PaddingState {
    /// 是否已经停止塑形（`stop` 之后不再加填充）。
    ///
    /// 停止后 `shape` 只是把数据原样复制一遍；调用方可以直接写原切片，
    /// 避免每个 PSH 都多一次整帧复制与结果容器分配。
    pub(super) fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// 与 `shape` 相同的长度上限校验，供快路径复用。
    pub(super) fn validate(data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_FRAME + 1024 {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn shape(&mut self, data: &[u8], scheme: &Scheme) -> io::Result<Vec<Vec<u8>>> {
        Self::validate(data)?;
        if self.stopped {
            return Ok(vec![data.to_vec()]);
        }
        self.packet = self.packet.checked_add(1).ok_or_else(invalid)?;
        if self.packet >= scheme.stop {
            self.stopped = true;
            return Ok(vec![data.to_vec()]);
        }
        let mut rest = data;
        let mut blocks = Vec::new();
        for item in scheme
            .records
            .get(&self.packet)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let size = match *item {
                Item::Check if rest.is_empty() => return Ok(blocks),
                Item::Check => continue,
                Item::Range(min, max) => random_range(min, max)?,
            };
            if rest.len() > size {
                blocks.push(rest[..size].to_vec());
                rest = &rest[size..];
                continue;
            }
            let mut block = Vec::with_capacity(size + size.div_ceil(MAX_FRAME) * HEADER);
            if !rest.is_empty() {
                block.extend_from_slice(rest);
                rest = &[];
                // 业务存在时，补齐的长度含Waste头；余量<=7不产生假帧。
                while size.saturating_sub(block.len()) > HEADER {
                    let length = (size - block.len() - HEADER).min(MAX_FRAME);
                    waste(&mut block, length);
                }
            } else {
                let mut remaining = size;
                while remaining > 0 {
                    let length = remaining.min(MAX_FRAME);
                    waste(&mut block, length);
                    remaining -= length;
                }
            }
            blocks.push(block);
        }
        if !rest.is_empty() {
            blocks.push(rest.to_vec());
        }
        Ok(blocks)
    }
}
fn waste(output: &mut Vec<u8>, length: usize) {
    output.extend_from_slice(&[0, 0, 0, 0, 0]);
    output.extend_from_slice(&(length as u16).to_be_bytes());
    output.resize(output.len() + length, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_text_digest_and_handshake_match_reference() {
        let scheme = Scheme::parse(DEFAULT_SCHEME).unwrap();
        assert_eq!(scheme.md5(), "75cff2ad89aadf5e257059ee571ebe11");
        assert_eq!(scheme.handshake_size().unwrap(), 30);
    }
    #[test]
    fn deterministic_sizes_check_marks_and_stop_preserve_frames() {
        let scheme = Scheme::parse("stop=3\n0=4-4\n1=4-4,20-20,c,99-99\n2=9-9").unwrap();
        let mut state = PaddingState::default();
        let data = b"abcdefghijkl";
        let blocks = state.shape(data, &scheme).unwrap();
        assert_eq!(&blocks[0], b"abcd");
        assert_eq!(&blocks[1][..8], b"efghijkl");
        assert_eq!(blocks[1].len(), 20);
        assert_eq!(&blocks[1][8..15], &[0, 0, 0, 0, 0, 0, 5]);
        assert_eq!(&blocks[1][15..], &[0; 5]);
        assert_eq!(blocks.len(), 2);
        assert_eq!(
            state.shape(b"hello", &scheme).unwrap(),
            vec![b"hello".to_vec()]
        );
        assert_eq!(
            state.shape(b"raw-stop", &scheme).unwrap(),
            vec![b"raw-stop".to_vec()]
        );
        // 已stop的会话不因更新更大stop重新整形。
        let update = Scheme::parse("stop=-1\n4=100-100").unwrap();
        assert_eq!(
            state.shape(b"still-raw", &update).unwrap(),
            vec![b"still-raw".to_vec()]
        );
    }
    #[test]
    fn empty_data_padding_uses_payload_size_plus_waste_header() {
        let scheme = Scheme::parse("stop=2\n1=9-9,3-3").unwrap();
        let blocks = PaddingState::default().shape(&[], &scheme).unwrap();
        assert_eq!(blocks.iter().map(Vec::len).collect::<Vec<_>>(), [16, 10]);
        assert_eq!(&blocks[0][..7], &[0, 0, 0, 0, 0, 0, 9]);
    }
    #[test]
    fn parsing_matches_duplicate_reverse_canonical_and_ignored_items() {
        let scheme =
            Scheme::parse("stop=1\nstop=-1\n0=5-5\n01=99-99\n1=12-10,bad,0-4,c\nunknown=x")
                .unwrap();
        assert_eq!(scheme.stop, u32::MAX);
        assert!(!scheme.records.contains_key(&1_000));
        assert_eq!(scheme.records.len(), 2);
        for _ in 0..64 {
            assert!((10..12).contains(&random_range(10, 12).unwrap()));
        }
        assert_ne!(
            scheme.md5(),
            Scheme::parse(&(scheme.raw().to_owned() + "\n"))
                .unwrap()
                .md5()
        );
    }
    #[test]
    fn malformed_updates_keep_previous_scheme_and_are_isolated() {
        let shared = SharedScheme::default();
        let other = SharedScheme::default();
        let before = shared.snapshot();
        for raw in [
            b"".as_slice(),
            b"stop=bad",
            b"stop=8\n1=999999999-999999999",
            b"stop=8\n0=65536-65536",
        ] {
            assert!(!shared.update(raw));
            assert_eq!(shared.snapshot().md5(), before.md5());
        }
        assert!(shared.update(b"stop=0\n0=2-2"));
        assert_eq!(shared.snapshot().handshake_size().unwrap(), 2);
        assert_eq!(other.snapshot().md5(), before.md5());
        assert!(Scheme::parse(&"x".repeat(65536)).is_err());
    }
}

#[cfg(test)]
mod stopped_fast_path_tests {
    use super::*;

    /// 快路径的前提：`stop` 之后 `shape` 只原样返回一份数据，不再加填充。
    ///
    /// `write_blocks` 在 `is_stopped()` 为真时直接写原切片，因此这里必须
    /// 保证两件事：状态判断准确、且 `shape` 在该状态下不改变字节。
    #[test]
    fn stopped_state_is_exact_and_adds_no_padding() {
        let scheme = Scheme::parse("stop=2\n0=4-4\n1=9-9").unwrap();
        let mut state = PaddingState::default();
        let data = b"abcdefghijkl";

        // 第 0 包：仍在塑形，会拆分并加 Waste。
        assert!(!state.is_stopped());
        let shaped = state.shape(data, &scheme).unwrap();
        assert!(!shaped.is_empty());

        // 第 1 包：`packet` 到达 stop，`shape` 自身把它置为停止。
        let crossing = state.shape(data, &scheme).unwrap();
        assert_eq!(
            crossing,
            vec![data.to_vec()],
            "跨越 stop 的这一包不再加填充"
        );
        assert!(state.is_stopped(), "跨越 stop 后状态必须为停止");

        // 之后：快路径与 shape 的输出必须完全一致。
        let after = state.shape(data, &scheme).unwrap();
        assert_eq!(
            after,
            vec![data.to_vec()],
            "停止后 shape 必须原样返回，快路径才等价"
        );
        assert_eq!(after.len(), 1);
    }

    /// 快路径仍要拒绝超长帧，不能因为跳过 `shape` 就绕过上限。
    #[test]
    fn stopped_fast_path_still_rejects_oversized_frames() {
        let mut state = PaddingState::default();
        let scheme = Scheme::parse("stop=0\n").unwrap();
        // stop=0：第一包即停止。
        let _ = state.shape(b"x", &scheme);
        assert!(state.is_stopped());
        let oversized = vec![0u8; MAX_FRAME + 1025];
        assert!(
            PaddingState::validate(&oversized).is_err(),
            "超长帧必须被拒绝"
        );
        assert!(state.shape(&oversized, &scheme).is_err());
    }
}
