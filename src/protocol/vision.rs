//! 不拥有 IO 的 Vision 增量 codec。
//!
//! 接收端只输入外层 TLS 已解密的明文。同一次 `consume` 内 End/Direct
//! 之后的尾部也是正文，不再扫描 UUID；`is_direct` 只通知承载在本批明文
//! 排空后停止输入外层 TLS。发送端只生成一个有限块，提交外层 TLS/Raw
//! 转换及部分写游标由拥有输出块的承载负责。VLESS 响应头不属于本 codec。
//!
//! 初始 UUID 探测是本项目的一次性透明策略，不复刻三家参考接收器各异的
//! 单 buffer 探测行为。这里的实现来自本地 wire 契约，不复制参考实现代码。

use std::io;

mod inspector;
pub use inspector::{Decision, Direction, Inspector};

/// 每个发送块保守预留首 UUID 和头后允许的最大正文。
pub const MAX_CONTENT: usize = 8171;
const MAX_BLOCK: usize = 8192;
const PREFIX_LEN: usize = 16;
const HEADER_LEN: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Command {
    Continue = 0,
    End = 1,
    Direct = 2,
}

impl TryFrom<u8> for Command {
    type Error = io::Error;

    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            0 => Ok(Self::Continue),
            1 => Ok(Self::End),
            2 => Ok(Self::Direct),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "未知 Vision command",
            )),
        }
    }
}

#[derive(Clone, Copy)]
enum ReadState {
    Probe(usize),
    Header {
        bytes: [u8; HEADER_LEN],
        used: usize,
        first: bool,
    },
    Block {
        command: Command,
        content: usize,
        padding: usize,
    },
    Plain,
    Direct,
    Failed,
}

/// UUID 及头只使用固定小缓冲；正文/padding 均以剩余计数流式处理。
///
/// 不按 peer 提供的 u16 长度分配正文或 padding 缓冲。调用者拥有 `output`
/// 并应在有界外层明文批次之间及时排空它。
pub struct Decoder {
    uuid: [u8; PREFIX_LEN],
    state: ReadState,
}

impl Decoder {
    pub fn new(uuid: [u8; PREFIX_LEN]) -> Self {
        Self {
            uuid,
            state: ReadState::Probe(0),
        }
    }

    /// 成功时消费整个 `input` 并返回其长度；只向 `output` 追加业务字节。
    ///
    /// End/Direct 在完整头、content 和 padding 全部完成后才提交；同次输入
    /// 的剩余字节原样追加。发生错误后永久失败，不允许重新猜测或继续解析。
    /// 错误前已经追加的有效正文不回滚，但错误块的未知命令正文绝不交付。
    pub fn consume(&mut self, input: &[u8], output: &mut Vec<u8>) -> io::Result<usize> {
        let mut cursor = 0;
        loop {
            match self.state {
                ReadState::Probe(mut matched) => {
                    while cursor < input.len() && matched < PREFIX_LEN {
                        if input[cursor] != self.uuid[matched] {
                            output.extend_from_slice(&self.uuid[..matched]);
                            output.extend_from_slice(&input[cursor..]);
                            self.state = ReadState::Plain;
                            return Ok(input.len());
                        }
                        cursor += 1;
                        matched += 1;
                    }
                    self.state = if matched == PREFIX_LEN {
                        Self::header(true)
                    } else {
                        ReadState::Probe(matched)
                    };
                    if matched < PREFIX_LEN {
                        break;
                    }
                }
                ReadState::Header {
                    mut bytes,
                    mut used,
                    first,
                } => {
                    let count = (HEADER_LEN - used).min(input.len() - cursor);
                    bytes[used..used + count].copy_from_slice(&input[cursor..cursor + count]);
                    used += count;
                    cursor += count;
                    if used < HEADER_LEN {
                        self.state = ReadState::Header { bytes, used, first };
                        break;
                    }
                    let command = match Command::try_from(bytes[0]) {
                        Ok(command) => command,
                        Err(error) => {
                            self.state = ReadState::Failed;
                            return Err(error);
                        }
                    };
                    self.state = ReadState::Block {
                        command,
                        content: usize::from(u16::from_be_bytes([bytes[1], bytes[2]])),
                        padding: usize::from(u16::from_be_bytes([bytes[3], bytes[4]])),
                    };
                }
                ReadState::Block {
                    command,
                    mut content,
                    mut padding,
                } => {
                    let count = content.min(input.len() - cursor);
                    output.extend_from_slice(&input[cursor..cursor + count]);
                    cursor += count;
                    content -= count;
                    if content == 0 {
                        let count = padding.min(input.len() - cursor);
                        cursor += count;
                        padding -= count;
                    }
                    if content != 0 || padding != 0 {
                        self.state = ReadState::Block {
                            command,
                            content,
                            padding,
                        };
                        break;
                    }
                    self.state = match command {
                        Command::Continue => Self::header(false),
                        Command::End => ReadState::Plain,
                        Command::Direct => ReadState::Direct,
                    };
                }
                ReadState::Plain | ReadState::Direct => {
                    output.extend_from_slice(&input[cursor..]);
                    return Ok(input.len());
                }
                ReadState::Failed => return Err(failed()),
            }
        }
        Ok(cursor)
    }

    /// 真正消费完 Direct 块后为 true，与本端 Inspector 无关。
    pub fn is_direct(&self) -> bool {
        matches!(self.state, ReadState::Direct)
    }

    /// End 或首次 UUID 明确不匹配后为 true，仍继续使用外层 TLS。
    pub fn is_plain(&self) -> bool {
        matches!(self.state, ReadState::Plain)
    }

    /// 初始空流、完整 Continue 边界及 Plain/Direct 的 EOF 正常；其他均截断。
    /// EOF 截断同样闩锁失败，之后不能继续输入。
    pub fn eof(&mut self) -> io::Result<()> {
        match self.state {
            ReadState::Probe(0)
            | ReadState::Header {
                used: 0,
                first: false,
                ..
            }
            | ReadState::Plain
            | ReadState::Direct => Ok(()),
            ReadState::Failed => Err(failed()),
            _ => {
                self.state = ReadState::Failed;
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "截断的 Vision 前缀或块",
                ))
            }
        }
    }

    fn header(first: bool) -> ReadState {
        ReadState::Header {
            bytes: [0; HEADER_LEN],
            used: 0,
            first,
        }
    }
}

fn failed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Vision codec 已失败")
}

/// 发送方向自己的首 UUID 状态，不与接收端共享。
///
/// 每次只生成一个完整块，返回 Vec 由承载持有并用游标排空；重试底层写入
/// 不应再次调用 encode。End/Direct 编码后不再接受新块，后续正文由承载直写。
pub struct Encoder {
    uuid: [u8; PREFIX_LEN],
    first: bool,
    finished: bool,
    failed: bool,
}

impl Encoder {
    pub fn new(uuid: [u8; PREFIX_LEN]) -> Self {
        Self {
            uuid,
            first: true,
            finished: false,
            failed: false,
        }
    }

    /// `long_padding` 表示已经识别到内层 TLS；仅正文小于 900 时启用长分布。
    pub fn encode(
        &mut self,
        command: Command,
        body: &[u8],
        long_padding: bool,
    ) -> io::Result<Vec<u8>> {
        self.encode_with_random(command, body, long_padding, &mut secure_random)
    }

    /// 注入随机字节来源以独立验证 wire 和分布边界；生产调用 `encode`。
    /// 随机失败永久终止编码器；无效正文长度不消耗首 UUID 或提交命令。
    pub fn encode_with_random<F>(
        &mut self,
        command: Command,
        body: &[u8],
        long_padding: bool,
        random: &mut F,
    ) -> io::Result<Vec<u8>>
    where
        F: FnMut(&mut [u8]) -> io::Result<()> + ?Sized,
    {
        if self.failed {
            return Err(failed());
        }
        if self.finished {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Vision padding 已结束",
            ));
        }
        if body.len() > MAX_CONTENT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Vision 正文超过单块上限",
            ));
        }
        let result = self.build(command, body, long_padding, random);
        match result {
            Ok(block) => {
                self.first = false;
                self.finished = command != Command::Continue;
                Ok(block)
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }

    fn build<F>(
        &self,
        command: Command,
        body: &[u8],
        long_padding: bool,
        random: &mut F,
    ) -> io::Result<Vec<u8>>
    where
        F: FnMut(&mut [u8]) -> io::Result<()> + ?Sized,
    {
        let padding = if long_padding && body.len() < 900 {
            uniform(500, random)? + 900 - body.len()
        } else {
            uniform(256, random)?
        }
        .min(MAX_BLOCK - PREFIX_LEN - HEADER_LEN - body.len());
        let prefix = if self.first { PREFIX_LEN } else { 0 };
        let mut block = Vec::with_capacity(prefix + HEADER_LEN + body.len() + padding);
        if self.first {
            block.extend_from_slice(&self.uuid);
        }
        block.push(command as u8);
        block.extend_from_slice(&(body.len() as u16).to_be_bytes());
        block.extend_from_slice(&(padding as u16).to_be_bytes());
        block.extend_from_slice(body);
        let offset = block.len();
        block.resize(offset + padding, 0);
        if padding != 0 {
            random(&mut block[offset..])?;
        }
        Ok(block)
    }
}

fn secure_random(bytes: &mut [u8]) -> io::Result<()> {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(bytes)
        .map_err(|_| io::Error::other("Vision 安全随机源失败"))
}

// 对安全随机字节做拒绝采样，不实现 PRNG；上界固定为 256 或 500。
fn uniform<F>(upper: u32, random: &mut F) -> io::Result<usize>
where
    F: FnMut(&mut [u8]) -> io::Result<()> + ?Sized,
{
    let range = u64::from(u32::MAX) + 1;
    let limit = range / u64::from(upper) * u64::from(upper);
    loop {
        let mut bytes = [0; 4];
        random(&mut bytes)?;
        let sample = u32::from_be_bytes(bytes);
        if u64::from(sample) < limit {
            return Ok((sample % upper) as usize);
        }
    }
}

#[cfg(test)]
mod tests;
