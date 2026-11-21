//! 只观察业务字节的有限 TLS 元数据识别器，不解密、不修改或缓存待转发业务。

use super::{Command, MAX_CONTENT};

const MAX_RECORDS: usize = 8;
const MAX_BYTES: usize = 65536;
const MAX_RECORD_PAYLOAD: usize = 16384 + 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Uplink,
    Downlink,
}

impl Direction {
    fn index(self) -> usize {
        match self {
            Self::Uplink => 0,
            Self::Downlink => 1,
        }
    }
}

/// 本次接受的输入前缀及该前缀最终块的 command。
///
/// `consumed` 始终不大于 min(input.len(), MAX_CONTENT)，非空输入总有进展。
/// Continue 后继续观察下一前缀；End 后余量走无 padding 外层 TLS；Direct
/// 后余量走 Raw。Direct 必定恰在完整 ApplicationData 记录末尾，即使记录
/// 起始于若干次更早的 observe。此对象不负责输出或提交承载转换。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    pub consumed: usize,
    pub command: Command,
}

/// 双向共享 TLS 事实及总计 8 记录/65536 字节预算；记录进度和发送状态独立。
///
/// 必须各方向恰好观察每个业务字节一次，不能观察 Vision 头、padding 或
/// VLESS 响应头。上行收到 wire Direct 后仍可把解包/Raw 业务提供给这里，
/// 接收 Direct 不以此对象的判定为前提。只读取 Downlink 的 ServerHello，
/// 防止把上行任意类型 2 握手当成目标服务端的协商事实。
#[derive(Default)]
pub struct Inspector {
    streams: [RecordTracker; 2],
    states: [SendState; 2],
    records: usize,
    bytes: usize,
    tls_seen: bool,
    tls13: bool,
    rejected: bool,
}

#[derive(Clone, Copy, Default)]
enum SendState {
    #[default]
    Inspect,
    End,
    Direct,
}

impl Inspector {
    pub fn new() -> Self {
        Self::default()
    }

    /// 接受至多 MAX_CONTENT 字节；仅 Direct 会在该前缀中间提早截断。
    /// 缺少事实时 Continue；非 TLS、不允许的协商或预算耗尽时 End。
    /// 终止方向后重复调用只返回该方向已提交的命令，不再花费检查预算。
    pub fn observe(&mut self, direction: Direction, data: &[u8]) -> Decision {
        let count = data.len().min(MAX_CONTENT);
        let index = direction.index();
        let state = self.states[index];
        let command = match state {
            SendState::Direct => Some(Command::Direct),
            SendState::End => Some(Command::End),
            SendState::Inspect if self.rejected => {
                self.states[index] = SendState::End;
                Some(Command::End)
            }
            SendState::Inspect => None,
        };
        if let Some(command) = command {
            return Decision {
                consumed: count,
                command,
            };
        }
        for (offset, &byte) in data[..count].iter().enumerate() {
            if self.bytes >= MAX_BYTES
                || self.records >= MAX_RECORDS && self.streams[index].at_boundary()
            {
                return self.end(index, count);
            }
            // 第一字节即占用记录预算，双向半个记录头也不能各多启动一条。
            if self.streams[index].at_boundary() {
                self.records += 1;
            }
            self.bytes += 1;
            let event = self.streams[index].push(byte, direction);
            if event.invalid {
                return self.end(index, count);
            }
            if event.header_complete {
                self.tls_seen = true;
            }
            match event.hello {
                Verdict::Tls13 => self.tls13 = true,
                Verdict::Reject => return self.end(index, count),
                Verdict::Unknown => {}
            }
            if event.application_complete && self.tls13 {
                self.states[index] = SendState::Direct;
                return Decision {
                    consumed: offset + 1,
                    command: Command::Direct,
                };
            }
            if self.bytes == MAX_BYTES || self.records == MAX_RECORDS && event.record_complete {
                return self.end(index, count);
            }
        }
        Decision {
            consumed: count,
            command: Command::Continue,
        }
    }

    /// 已见合法 TLS 记录头，可作为 Encoder 的 long_padding 参数。
    pub fn is_tls(&self) -> bool {
        self.tls_seen
    }

    fn end(&mut self, index: usize, consumed: usize) -> Decision {
        self.rejected = true;
        self.states[index] = SendState::End;
        Decision {
            consumed,
            command: Command::End,
        }
    }
}

#[derive(Default)]
struct RecordTracker {
    header: [u8; 5],
    used: usize,
    remaining: usize,
    handshake: Handshake,
}

#[derive(Default)]
struct Event {
    invalid: bool,
    header_complete: bool,
    record_complete: bool,
    application_complete: bool,
    hello: Verdict,
}

impl RecordTracker {
    fn at_boundary(&self) -> bool {
        self.used == 0
    }

    fn push(&mut self, byte: u8, direction: Direction) -> Event {
        let mut event = Event::default();
        if self.used < self.header.len() {
            self.header[self.used] = byte;
            self.used += 1;
            event.invalid = match self.used {
                1 => !matches!(byte, 20..=23),
                2 => byte != 3,
                3 => byte > 3,
                _ => false,
            };
            if event.invalid || self.used < self.header.len() {
                return event;
            }
            self.remaining = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
            if self.remaining > MAX_RECORD_PAYLOAD {
                event.invalid = true;
                return event;
            }
            event.header_complete = true;
        } else {
            self.remaining -= 1;
            if self.header[0] == 22 && direction == Direction::Downlink {
                event.hello = self.handshake.push(byte);
            }
        }
        if self.remaining == 0 {
            event.record_complete = true;
            event.application_complete = self.header[0] == 23;
            self.used = 0;
        }
        event
    }
}

#[derive(Clone, Copy, Default)]
enum Verdict {
    #[default]
    Unknown,
    Tls13,
    Reject,
}

#[derive(Default)]
struct Handshake {
    header: [u8; 4],
    used: usize,
    remaining: usize,
    // 不预分配 peer 声明的长度；只缓存实际已观察到的 ServerHello 字节。
    // 两方向全局字节预算使整个对象最多缓存 65536 字节；其他握手只计数。
    hello: Option<Vec<u8>>,
}

impl Handshake {
    fn push(&mut self, byte: u8) -> Verdict {
        if self.used < self.header.len() {
            self.header[self.used] = byte;
            self.used += 1;
            if self.used != self.header.len() {
                return Verdict::Unknown;
            }
            self.remaining = usize::from(self.header[1]) << 16
                | usize::from(self.header[2]) << 8
                | usize::from(self.header[3]);
            if self.header[0] == 2 {
                if self.remaining > MAX_BYTES - self.header.len() {
                    return Verdict::Reject;
                }
                self.hello = Some(Vec::new());
            }
        } else {
            self.remaining -= 1;
            if let Some(hello) = self.hello.as_mut() {
                hello.push(byte);
            }
        }
        if self.remaining != 0 {
            return Verdict::Unknown;
        }
        self.used = 0;
        self.hello
            .take()
            .map_or(Verdict::Unknown, |hello| server_hello(&hello))
    }
}

// 只解析确定 TLS 版本/套件所需的公开 ServerHello 元数据，完整检查向量边界。
fn server_hello(body: &[u8]) -> Verdict {
    let mut reader = Fields(body);
    if reader.take(2) != Some(&[3, 3][..]) || reader.take(32).is_none() {
        return Verdict::Reject;
    }
    let Some(session_len) = reader.byte() else {
        return Verdict::Reject;
    };
    if session_len > 32 || reader.take(usize::from(session_len)).is_none() {
        return Verdict::Reject;
    }
    let Some(cipher) = reader.u16() else {
        return Verdict::Reject;
    };
    if !matches!(cipher, 0x1301..=0x1304) || reader.byte() != Some(0) {
        return Verdict::Reject;
    }
    let Some(extension_len) = reader.u16() else {
        return Verdict::Reject;
    };
    if usize::from(extension_len) != reader.0.len() {
        return Verdict::Reject;
    }
    let mut version = None;
    while !reader.0.is_empty() {
        let (Some(kind), Some(length)) = (reader.u16(), reader.u16()) else {
            return Verdict::Reject;
        };
        let Some(value) = reader.take(usize::from(length)) else {
            return Verdict::Reject;
        };
        if kind == 43 {
            if version.is_some() || value.len() != 2 {
                return Verdict::Reject;
            }
            version = Some(value == [3, 4]);
        }
    }
    if version == Some(true) {
        Verdict::Tls13
    } else {
        Verdict::Reject
    }
}

struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let result = self.0.get(..count)?;
        self.0 = &self.0[count..];
        Some(result)
    }

    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }
}
