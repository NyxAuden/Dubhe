//! Xray mKCP 分段线格式（`transport/internet/kcp/segment.go` 的等价实现）。
//!
//! 一个 UDP 载荷可以顺序承载多个分段；解析在遇到截断或未知长度时停止。

pub const COMMAND_ACK: u8 = 0;
pub const COMMAND_DATA: u8 = 1;
pub const COMMAND_TERMINATE: u8 = 2;
pub const COMMAND_PING: u8 = 3;

/// `conv(2) + cmd(1) + opt(1)`。
pub const SEGMENT_HEADER: usize = 4;
/// 数据段除载荷外的固定开销：时间戳、序号、sendingNext、长度。
pub const DATA_OVERHEAD: usize = SEGMENT_HEADER + 4 + 4 + 4 + 2;
/// 单个 ACK 段最多携带的确认号数量（Xray `ackNumberLimit`）。
pub const ACK_LIMIT: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    Data(DataSegment),
    Ack(AckSegment),
    Cmd(CmdSegment),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSegment {
    pub conv: u16,
    pub option: u8,
    pub timestamp: u32,
    pub number: u32,
    pub sending_next: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckSegment {
    pub conv: u16,
    pub option: u8,
    pub receiving_window: u32,
    pub receiving_next: u32,
    pub timestamp: u32,
    pub numbers: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdSegment {
    pub conv: u16,
    pub command: u8,
    pub option: u8,
    pub sending_next: u32,
    pub receiving_next: u32,
    pub peer_rto: u32,
}

impl Segment {
    pub fn conv(&self) -> u16 {
        match self {
            Self::Data(segment) => segment.conv,
            Self::Ack(segment) => segment.conv,
            Self::Cmd(segment) => segment.conv,
        }
    }

    pub fn command(&self) -> u8 {
        match self {
            Self::Data(_) => COMMAND_DATA,
            Self::Ack(_) => COMMAND_ACK,
            Self::Cmd(segment) => segment.command,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Data(segment) => {
                let mut bytes = Vec::with_capacity(DATA_OVERHEAD + segment.payload.len());
                put_head(&mut bytes, segment.conv, COMMAND_DATA, segment.option);
                bytes.extend_from_slice(&segment.timestamp.to_be_bytes());
                bytes.extend_from_slice(&segment.number.to_be_bytes());
                bytes.extend_from_slice(&segment.sending_next.to_be_bytes());
                bytes.extend_from_slice(&(segment.payload.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&segment.payload);
                bytes
            }
            Self::Ack(segment) => {
                let mut bytes = Vec::with_capacity(17 + segment.numbers.len() * 4);
                put_head(&mut bytes, segment.conv, COMMAND_ACK, segment.option);
                bytes.extend_from_slice(&segment.receiving_window.to_be_bytes());
                bytes.extend_from_slice(&segment.receiving_next.to_be_bytes());
                bytes.extend_from_slice(&segment.timestamp.to_be_bytes());
                bytes.push(segment.numbers.len() as u8);
                for number in &segment.numbers {
                    bytes.extend_from_slice(&number.to_be_bytes());
                }
                bytes
            }
            Self::Cmd(segment) => {
                let mut bytes = Vec::with_capacity(16);
                put_head(&mut bytes, segment.conv, segment.command, segment.option);
                bytes.extend_from_slice(&segment.sending_next.to_be_bytes());
                bytes.extend_from_slice(&segment.receiving_next.to_be_bytes());
                bytes.extend_from_slice(&segment.peer_rto.to_be_bytes());
                bytes
            }
        }
    }
}

fn put_head(bytes: &mut Vec<u8>, conv: u16, command: u8, option: u8) {
    bytes.extend_from_slice(&conv.to_be_bytes());
    bytes.push(command);
    bytes.push(option);
}

/// 解析一段 UDP 载荷；格式错误的分段结束解析，不 panic。
pub fn parse(mut buf: &[u8]) -> Vec<Segment> {
    let mut segments = Vec::new();
    while buf.len() >= SEGMENT_HEADER {
        let conv = u16::from_be_bytes([buf[0], buf[1]]);
        let command = buf[2];
        let option = buf[3];
        let body = &buf[SEGMENT_HEADER..];
        let (segment, used) = match command {
            COMMAND_DATA => {
                if body.len() < 14 {
                    break;
                }
                let timestamp = u32::from_be_bytes(body[0..4].try_into().expect("4字节"));
                let number = u32::from_be_bytes(body[4..8].try_into().expect("4字节"));
                let sending_next = u32::from_be_bytes(body[8..12].try_into().expect("4字节"));
                let length =
                    usize::from(u16::from_be_bytes(body[12..14].try_into().expect("2字节")));
                if body.len() < 14 + length {
                    break;
                }
                (
                    Segment::Data(DataSegment {
                        conv,
                        option,
                        timestamp,
                        number,
                        sending_next,
                        payload: body[14..14 + length].to_vec(),
                    }),
                    14 + length,
                )
            }
            COMMAND_ACK => {
                if body.len() < 13 {
                    break;
                }
                let receiving_window = u32::from_be_bytes(body[0..4].try_into().expect("4字节"));
                let receiving_next = u32::from_be_bytes(body[4..8].try_into().expect("4字节"));
                let timestamp = u32::from_be_bytes(body[8..12].try_into().expect("4字节"));
                let count = usize::from(body[12]);
                if body.len() < 13 + count * 4 {
                    break;
                }
                let mut numbers = Vec::with_capacity(count);
                for index in 0..count {
                    let offset = 13 + index * 4;
                    numbers.push(u32::from_be_bytes(
                        body[offset..offset + 4].try_into().expect("4字节"),
                    ));
                }
                (
                    Segment::Ack(AckSegment {
                        conv,
                        option,
                        receiving_window,
                        receiving_next,
                        timestamp,
                        numbers,
                    }),
                    13 + count * 4,
                )
            }
            command => {
                if body.len() < 12 {
                    break;
                }
                (
                    Segment::Cmd(CmdSegment {
                        conv,
                        command,
                        option,
                        sending_next: u32::from_be_bytes(body[0..4].try_into().expect("4字节")),
                        receiving_next: u32::from_be_bytes(body[4..8].try_into().expect("4字节")),
                        peer_rto: u32::from_be_bytes(body[8..12].try_into().expect("4字节")),
                    }),
                    12,
                )
            }
        };
        segments.push(segment);
        buf = &buf[SEGMENT_HEADER + used..];
    }
    segments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_round_trip() {
        let segment = Segment::Data(DataSegment {
            conv: 0x1234,
            option: 1,
            timestamp: 7,
            number: 9,
            sending_next: 3,
            payload: b"hello".to_vec(),
        });
        let bytes = segment.encode();
        assert_eq!(bytes.len(), DATA_OVERHEAD + 5);
        assert_eq!(parse(&bytes), vec![segment]);
    }

    #[test]
    fn ack_and_command_round_trip() {
        let ack = Segment::Ack(AckSegment {
            conv: 1,
            option: 0,
            receiving_window: 64,
            receiving_next: 5,
            timestamp: 11,
            numbers: vec![1, 2, 3],
        });
        let cmd = Segment::Cmd(CmdSegment {
            conv: 1,
            command: COMMAND_PING,
            option: 0,
            sending_next: 4,
            receiving_next: 6,
            peer_rto: 120,
        });
        let mut bytes = ack.encode();
        bytes.extend(cmd.encode());
        assert_eq!(parse(&bytes), vec![ack, cmd]);
    }

    #[test]
    fn multiple_data_segments_share_one_datagram() {
        let one = Segment::Data(DataSegment {
            conv: 2,
            option: 0,
            timestamp: 1,
            number: 1,
            sending_next: 0,
            payload: b"a".to_vec(),
        });
        let two = Segment::Data(DataSegment {
            conv: 2,
            option: 0,
            timestamp: 1,
            number: 2,
            sending_next: 0,
            payload: b"bc".to_vec(),
        });
        let mut bytes = one.encode();
        bytes.extend(two.encode());
        assert_eq!(parse(&bytes), vec![one, two]);
    }

    #[test]
    fn truncated_and_trailing_bytes_stop_without_panic() {
        let bytes = Segment::Data(DataSegment {
            conv: 1,
            option: 0,
            timestamp: 0,
            number: 0,
            sending_next: 0,
            payload: vec![0x5a; 8],
        })
        .encode();
        assert!(parse(&bytes[..bytes.len() - 1]).is_empty());
        let mut trailing = bytes.clone();
        trailing.extend_from_slice(&[1, 2]);
        assert_eq!(parse(&trailing).len(), 1);
        assert!(parse(&[0, 1]).is_empty());
    }

    #[test]
    fn ack_count_is_bounded_by_the_wire_field() {
        let segment = Segment::Ack(AckSegment {
            conv: 0,
            option: 0,
            receiving_window: 0,
            receiving_next: 0,
            timestamp: 0,
            numbers: (0..ACK_LIMIT as u32).collect(),
        });
        let bytes = segment.encode();
        match &parse(&bytes)[0] {
            Segment::Ack(ack) => assert_eq!(ack.numbers.len(), ACK_LIMIT),
            other => panic!("应为ACK分段: {other:?}"),
        }
    }
}
