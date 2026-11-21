use super::*;

const UUID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

// 独立手写 wire 金样，不调用 Encoder 生成 Decoder 的预期输入。
const GOLDEN: &[u8] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, // UUID
    0, 0, 3, 0, 2, 0, 255, 17, 91, 92, // Continue, binary content + padding
    0, 0, 0, 0, 0, // empty Continue
    2, 0, 2, 0, 3, 65, 66, 81, 82, 83, // Direct
    9, 8, 7, // decrypted plaintext tail, not a new Vision header
];
const GOLDEN_BODY: &[u8] = &[0, 255, 17, 65, 66, 9, 8, 7];

fn decode_parts(parts: &[&[u8]]) -> (Decoder, Vec<u8>) {
    let mut decoder = Decoder::new(UUID);
    let mut output = Vec::new();
    for part in parts {
        assert_eq!(decoder.consume(part, &mut output).unwrap(), part.len());
    }
    decoder.eof().unwrap();
    (decoder, output)
}

#[test]
fn decoder_independent_wire_all_single_cuts_and_every_byte() {
    for cut in 0..=GOLDEN.len() {
        let (decoder, output) = decode_parts(&[&GOLDEN[..cut], &GOLDEN[cut..]]);
        assert_eq!(output, GOLDEN_BODY, "cut={cut}");
        assert!(decoder.is_direct());
        assert!(!decoder.is_plain());
    }
    let parts: Vec<_> = GOLDEN.chunks(1).collect();
    let (decoder, output) = decode_parts(&parts);
    assert_eq!(output, GOLDEN_BODY);
    assert!(decoder.is_direct());
}

#[test]
fn decoder_all_two_cuts_including_record_boundaries() {
    for left in 0..=GOLDEN.len() {
        for right in left..=GOLDEN.len() {
            let (decoder, output) =
                decode_parts(&[&GOLDEN[..left], &GOLDEN[left..right], &GOLDEN[right..]]);
            assert_eq!(output, GOLDEN_BODY, "cuts={left}/{right}");
            assert!(decoder.is_direct());
        }
    }
}

#[test]
fn decoder_does_not_commit_command_before_full_header_body_and_padding() {
    for command in [1, 2] {
        let mut decoder = Decoder::new(UUID);
        let mut output = Vec::new();
        decoder.consume(&UUID, &mut output).unwrap();
        decoder.consume(&[0, 0, 0, 0, 0], &mut output).unwrap();
        for byte in [command, 0, 1, 0, 2, b'x', 9] {
            decoder.consume(&[byte], &mut output).unwrap();
            assert!(!decoder.is_direct());
            assert!(!decoder.is_plain());
        }
        assert_eq!(output, b"x");
        decoder.consume(&[8], &mut output).unwrap();
        assert_eq!(decoder.is_direct(), command == 2);
        assert_eq!(decoder.is_plain(), command == 1);
        decoder.eof().unwrap();
    }
}

#[test]
fn decoder_zero_content_and_padding_and_terminal_tails() {
    for command in [0, 1, 2] {
        for padding in [0, 3] {
            let mut wire = UUID.to_vec();
            wire.extend_from_slice(&[command, 0, 0, 0, padding]);
            wire.extend(std::iter::repeat_n(99, usize::from(padding)));
            let (decoder, body) = decode_parts(&wire.chunks(1).collect::<Vec<_>>());
            assert!(body.is_empty());
            assert_eq!(decoder.is_plain(), command == 1);
            assert_eq!(decoder.is_direct(), command == 2);
        }
    }
    for command in [1, 2] {
        let mut wire = UUID.to_vec();
        wire.extend_from_slice(&[command, 0, 0, 0, 0]);
        // 一个完整 UUID + 伪未知头在 End/Direct 后也必须原样保留。
        let mut tail = UUID.to_vec();
        tail.extend_from_slice(&[255, 0, 0, 0, 0]);
        wire.extend_from_slice(&tail);
        let (mut decoder, mut output) = decode_parts(&[&wire]);
        decoder.consume(&tail, &mut output).unwrap();
        assert_eq!(output, tail.repeat(2));
    }
}

#[test]
fn decoder_u16_maximum_fields_are_streamed() {
    let mut decoder = Decoder::new(UUID);
    let mut output = Vec::new();
    decoder.consume(&UUID, &mut output).unwrap();
    decoder
        .consume(&[2, 255, 255, 255, 255], &mut output)
        .unwrap();
    let content: Vec<u8> = (0..65535).map(|n| (n % 251) as u8).collect();
    for part in content.chunks(117) {
        assert_eq!(decoder.consume(part, &mut output).unwrap(), part.len());
        assert!(!decoder.is_direct());
    }
    assert_eq!(output, content);
    for _ in 0..65534 {
        decoder.consume(&[0], &mut output).unwrap();
        assert!(!decoder.is_direct());
    }
    decoder.consume(&[0, b't'], &mut output).unwrap();
    assert!(decoder.is_direct());
    assert_eq!(output.len(), 65536);
    assert_eq!(output.last(), Some(&b't'));
    decoder.eof().unwrap();
    // 仅固定 UUID、头和几个计数，没有 peer 长度相关的内部缓冲。
    assert!(std::mem::size_of::<Decoder>() <= 80);
}

#[test]
fn decoder_prefix_mismatch_is_transparent_once_at_every_position() {
    for mismatch in 0..16 {
        let mut wire = UUID.to_vec();
        wire[mismatch] ^= 128;
        wire.extend_from_slice(&UUID);
        wire.extend_from_slice(&[255, 0, 1, 0, 0, b'z']);
        for cut in 0..=wire.len() {
            let (decoder, output) = decode_parts(&[&wire[..cut], &wire[cut..]]);
            assert!(decoder.is_plain());
            assert!(!decoder.is_direct());
            assert_eq!(output, wire, "mismatch={mismatch}, cut={cut}");
        }
    }
}

#[test]
fn decoder_eof_exact_boundary_rules_and_permanent_failures() {
    let mut wire = UUID.to_vec();
    wire.extend_from_slice(&[0, 0, 2, 0, 2, b'a', b'b', 9, 9]);
    let complete_continue = wire.len();
    wire.extend_from_slice(&[1, 0, 1, 0, 1, b'c', 9]);
    for cut in 0..=wire.len() {
        let mut decoder = Decoder::new(UUID);
        decoder.consume(&wire[..cut], &mut Vec::new()).unwrap();
        if [0, complete_continue, wire.len()].contains(&cut) {
            decoder.eof().unwrap();
        } else {
            assert_eq!(
                decoder.eof().unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
            assert_eq!(
                decoder.eof().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(decoder.consume(&wire[cut..], &mut Vec::new()).is_err());
        }
    }
    let mut decoder = Decoder::new(UUID);
    decoder.consume(&UUID, &mut Vec::new()).unwrap();
    // 不依据 command 单字节提前失败/切换，但完整未知头后永久失败。
    decoder.consume(&[255], &mut Vec::new()).unwrap();
    let mut output = Vec::new();
    assert_eq!(
        decoder
            .consume(&[0, 1, 0, 0, b'x'], &mut output)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert!(output.is_empty());
    assert!(decoder.consume(&[1, 0, 0, 0, 0], &mut output).is_err());
    assert!(decoder.eof().is_err());
}

fn zero_random(bytes: &mut [u8]) -> io::Result<()> {
    bytes.fill(0);
    Ok(())
}

fn random_sample(sample: u32) -> impl FnMut(&mut [u8]) -> io::Result<()> {
    let mut first = true;
    move |bytes| {
        if first {
            assert_eq!(bytes.len(), 4);
            bytes.copy_from_slice(&sample.to_be_bytes());
            first = false;
        } else {
            bytes.fill(0x5a);
        }
        Ok(())
    }
}

#[test]
fn encoder_independent_golden_and_own_first_uuid() {
    let mut encoder = Encoder::new(UUID);
    let first = encoder
        .encode_with_random(Command::Continue, b"hi", false, &mut zero_random)
        .unwrap();
    assert_eq!(
        first,
        [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 2, 0, 0, b'h', b'i'
        ]
    );
    let second = encoder
        .encode_with_random(Command::Direct, &[255], false, &mut zero_random)
        .unwrap();
    assert_eq!(second, [2, 0, 1, 0, 0, 255]);
    assert!(encoder.encode(Command::Continue, b"", false).is_err());
    // 没有独立 VLESS 响应头，输出第一字节就是 UUID，不是 00 00 响应。
    let another = Encoder::new([7; 16])
        .encode_with_random(Command::End, b"", false, &mut zero_random)
        .unwrap();
    assert_eq!(&another[..16], &[7; 16]);
}

#[test]
fn encoder_padding_distribution_limits_and_cap() {
    for (len, long, sample, expected) in [
        (0, true, 499, 1399),
        (0, true, 0, 900),
        (899, true, 499, 500),
        (900, true, 255, 255),
        (0, false, 255, 255),
        (8170, true, 255, 1),
        (8171, true, 255, 0),
    ] {
        let body = vec![0xf1; len];
        let wire = Encoder::new(UUID)
            .encode_with_random(Command::Continue, &body, long, &mut random_sample(sample))
            .unwrap();
        assert_eq!(usize::from(u16::from_be_bytes([wire[17], wire[18]])), len);
        assert_eq!(
            usize::from(u16::from_be_bytes([wire[19], wire[20]])),
            expected
        );
        assert_eq!(wire.len(), 21 + len + expected);
        assert!(wire.len() <= 8192);
        assert_eq!(&wire[21..21 + len], body);
        assert!(wire[21 + len..].iter().all(|byte| *byte == 0x5a));
    }
}

#[test]
fn encoder_invalid_large_content_preserves_first_prefix() {
    let mut encoder = Encoder::new(UUID);
    for len in [8172, 8192, 65536] {
        assert_eq!(
            encoder
                .encode(Command::End, &vec![0; len], false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    let block = encoder
        .encode_with_random(Command::End, b"", false, &mut zero_random)
        .unwrap();
    assert_eq!(&block[..16], UUID);
    assert_eq!(block.len(), 21);
}

#[test]
fn encoder_large_business_is_split_by_caller_with_only_last_command_terminal() {
    for length in [0, 8170, 8171, 8192, 50000] {
        let body: Vec<_> = (0..length).map(|n| (n % 241) as u8).collect();
        let mut encoder = Encoder::new(UUID);
        let mut wire = Vec::new();
        let chunks: Vec<_> = if body.is_empty() {
            vec![body.as_slice()]
        } else {
            body.chunks(MAX_CONTENT).collect()
        };
        for (index, part) in chunks.iter().enumerate() {
            let command = if index + 1 == chunks.len() {
                Command::End
            } else {
                Command::Continue
            };
            let block = encoder
                .encode_with_random(command, part, false, &mut zero_random)
                .unwrap();
            assert!(block.len() <= 8192);
            // 承载的部分输出只用游标，不重建或重放块；codec 自己没有隐含 IO。
            for short_write in block.chunks(3) {
                wire.extend_from_slice(short_write);
            }
        }
        let (decoder, decoded) = decode_parts(&wire.chunks(11).collect::<Vec<_>>());
        assert_eq!(decoded, body);
        assert!(decoder.is_plain());
    }
}

#[test]
fn encoder_unbiased_sampling_rejects_tail_and_random_failure_is_latched() {
    let mut calls = 0;
    let mut rng = |bytes: &mut [u8]| {
        calls += 1;
        if calls == 1 {
            bytes.copy_from_slice(&u32::MAX.to_be_bytes());
        } else if calls == 2 {
            bytes.copy_from_slice(&499u32.to_be_bytes());
        } else {
            bytes.fill(1);
        }
        Ok(())
    };
    let block = Encoder::new(UUID)
        .encode_with_random(Command::End, b"", true, &mut rng)
        .unwrap();
    assert_eq!(block.len(), 21 + 1399);
    assert_eq!(calls, 3);
    let mut encoder = Encoder::new(UUID);
    let mut failing = |_: &mut [u8]| Err(io::Error::other("故意失败"));
    assert!(
        encoder
            .encode_with_random(Command::Continue, b"", true, &mut failing)
            .is_err()
    );
    assert!(
        encoder
            .encode_with_random(Command::Continue, b"", false, &mut zero_random)
            .is_err()
    );
    // 真实生产公开随机 API 的小型 smoke，不检查具体随机值。
    assert!(
        Encoder::new(UUID)
            .encode(Command::End, b"ok", false)
            .is_ok()
    );
}

// 独立手写 TLS 记录/ServerHello，仅测试公开 wire 元数据，不使用 rustls 编码器。
fn record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut wire = vec![kind, 3, 3];
    wire.extend_from_slice(&(body.len() as u16).to_be_bytes());
    wire.extend_from_slice(body);
    wire
}

fn hello_message(cipher: u16, version: Option<[u8; 2]>) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0xa5; 32]);
    body.push(0); // session id
    body.extend_from_slice(&cipher.to_be_bytes());
    body.push(0); // compression
    if let Some(version) = version {
        body.extend_from_slice(&[0, 6, 0, 43, 0, 2]);
        body.extend_from_slice(&version);
    }
    let mut handshake = vec![2, 0, 0, body.len() as u8];
    handshake.extend(body);
    handshake
}

fn hello(cipher: u16) -> Vec<u8> {
    record(22, &hello_message(cipher, Some([3, 4])))
}

fn app(body: &[u8]) -> Vec<u8> {
    record(23, body)
}

fn observe_all(
    inspector: &mut Inspector,
    direction: Direction,
    data: &[u8],
    chunk: usize,
) -> Command {
    let mut cursor = 0;
    let mut command = Command::Continue;
    while cursor < data.len() {
        let end = (cursor + chunk).min(data.len());
        let decision = inspector.observe(direction, &data[cursor..end]);
        assert!(decision.consumed > 0);
        assert!(decision.consumed <= MAX_CONTENT);
        cursor += decision.consumed;
        command = decision.command;
    }
    command
}

#[test]
fn inspector_server_hello_all_cuts_and_allowed_ciphers() {
    for cipher in 0x1301..=0x1304 {
        let server = hello(cipher);
        for cut in 0..=server.len() {
            let mut inspector = Inspector::new();
            assert_eq!(
                inspector
                    .observe(Direction::Downlink, &server[..cut])
                    .command,
                Command::Continue
            );
            assert_eq!(
                inspector
                    .observe(Direction::Downlink, &server[cut..])
                    .command,
                Command::Continue
            );
            assert!(inspector.is_tls());
            let application = app(b"ciphertext");
            for &byte in &application[..application.len() - 1] {
                assert_eq!(
                    inspector.observe(Direction::Downlink, &[byte]).command,
                    Command::Continue
                );
            }
            assert_eq!(
                inspector
                    .observe(Direction::Downlink, &application[application.len() - 1..])
                    .command,
                Command::Direct
            );
        }
    }
}

#[test]
fn inspector_handshake_across_records_and_call_boundaries() {
    let message = hello_message(0x1301, Some([3, 4]));
    for record_cut in 0..=message.len() {
        let mut wire = record(22, &message[..record_cut]);
        // 允许位于握手片段之间的兼容 ChangeCipherSpec，不破坏握手进度。
        wire.extend(record(20, &[1]));
        wire.extend(record(22, &message[record_cut..]));
        let mut inspector = Inspector::new();
        assert_eq!(
            observe_all(&mut inspector, Direction::Downlink, &wire, 1),
            Command::Continue
        );
        assert_eq!(
            observe_all(&mut inspector, Direction::Uplink, &app(b"a"), 1),
            Command::Direct
        );
    }
}

#[test]
fn inspector_direct_stops_exactly_at_application_boundary_not_current_write() {
    let mut inspector = Inspector::new();
    inspector.observe(Direction::Downlink, &hello(0x1303));
    let application = app(&vec![33; 12000]);
    let first = inspector.observe(Direction::Downlink, &application);
    assert_eq!(
        first,
        Decision {
            consumed: 8171,
            command: Command::Continue
        }
    );
    let mut rest = application[first.consumed..].to_vec();
    rest.extend_from_slice(b"raw next bytes");
    let final_block = inspector.observe(Direction::Downlink, &rest);
    assert_eq!(final_block.consumed, application.len() - first.consumed);
    assert_eq!(final_block.command, Command::Direct);
    assert_eq!(&rest[final_block.consumed..], b"raw next bytes");
    // 另一个方向尚未 Direct，自有的完整记录边界才能独立切换。
    let other = app(b"other");
    assert_eq!(
        inspector.observe(Direction::Uplink, &other[..6]).command,
        Command::Continue
    );
    assert_eq!(
        inspector.observe(Direction::Uplink, &other[6..]).command,
        Command::Direct
    );
}

#[test]
fn inspector_same_app_record_has_identical_boundary_at_all_cuts() {
    let application = app(b"binary\x00\xff\x01");
    for cut in 0..=application.len() {
        let mut inspector = Inspector::new();
        inspector.observe(Direction::Downlink, &hello(0x1302));
        let left = inspector.observe(Direction::Downlink, &application[..cut]);
        assert_eq!(
            left.command,
            if cut == application.len() {
                Command::Direct
            } else {
                Command::Continue
            }
        );
        let mut tail = application[cut..].to_vec();
        tail.extend_from_slice(b"tail");
        let right = inspector.observe(Direction::Downlink, &tail);
        assert_eq!(right.command, Command::Direct);
        assert_eq!(
            right.consumed,
            if cut == application.len() {
                4
            } else {
                application.len() - cut
            }
        );
    }
}

#[test]
fn inspector_shared_facts_but_independent_progress_and_receive_direct() {
    let mut inspector = Inspector::new();
    let application = app(b"already started");
    assert_eq!(
        inspector
            .observe(Direction::Uplink, &application[..9])
            .command,
        Command::Continue
    );
    assert_eq!(
        observe_all(&mut inspector, Direction::Downlink, &hello(0x1304), 1),
        Command::Continue
    );
    assert_eq!(
        inspector
            .observe(Direction::Uplink, &application[9..])
            .command,
        Command::Direct
    );
    assert_eq!(
        inspector
            .observe(Direction::Downlink, &app(b"server"))
            .command,
        Command::Direct
    );
    // 对端在任何识别事实之前发出合法 Direct 也必须接收，包括非 TLS 正文。
    let mut decoder = Decoder::new(UUID);
    let mut output = Vec::new();
    decoder.consume(&UUID, &mut output).unwrap();
    decoder
        .consume(&[2, 0, 3, 0, 0, b'n', b'o', b't'], &mut output)
        .unwrap();
    assert!(decoder.is_direct());
    assert_eq!(output, b"not");
}

#[test]
fn inspector_rejects_tls12_unknown_suites_versions_and_non_tls() {
    let mut variants = vec![
        record(22, &hello_message(0xc02f, None)),
        record(22, &hello_message(0x1301, None)),
        record(22, &hello_message(0x1301, Some([3, 3]))),
        hello(0x1305),
        hello(0x9999),
        b"HTTP/1.1 200 OK\r\n".to_vec(),
        vec![22, 2, 3],
        vec![22, 3, 4],
        vec![22, 3, 3, 255, 255],
    ];
    let mut duplicate = hello_message(0x1301, Some([3, 4]));
    // supported_versions 重复且长度自洽仍拒绝。
    let length_index = duplicate.len() - 8;
    duplicate[length_index + 1] = 12;
    duplicate.extend_from_slice(&[0, 43, 0, 2, 3, 4]);
    duplicate[3] += 6;
    variants.push(record(22, &duplicate));
    for wire in variants {
        for chunk in [1, 17, 8171] {
            let mut inspector = Inspector::new();
            assert_eq!(
                observe_all(&mut inspector, Direction::Downlink, &wire, chunk),
                Command::End
            );
            assert_eq!(
                inspector.observe(Direction::Uplink, &app(b"x")).command,
                Command::End
            );
        }
    }
}

#[test]
fn inspector_no_premature_direct_without_complete_hello_or_on_uplink_hello() {
    let server = hello(0x1301);
    let mut inspector = Inspector::new();
    assert_eq!(
        inspector
            .observe(Direction::Downlink, &server[..server.len() - 1])
            .command,
        Command::Continue
    );
    assert_eq!(
        inspector.observe(Direction::Uplink, &app(b"x")).command,
        Command::Continue
    );
    inspector.observe(Direction::Downlink, &server[server.len() - 1..]);
    assert_eq!(
        inspector.observe(Direction::Uplink, &app(b"y")).command,
        Command::Direct
    );
    let mut inspector = Inspector::new();
    inspector.observe(Direction::Uplink, &server);
    assert_eq!(
        inspector.observe(Direction::Uplink, &app(b"x")).command,
        Command::Continue
    );
}

#[test]
fn inspector_record_and_byte_budgets_are_shared_and_finite() {
    let mut inspector = Inspector::new();
    let empty = record(20, &[]);
    for index in 0..8 {
        let direction = if index % 2 == 0 {
            Direction::Uplink
        } else {
            Direction::Downlink
        };
        assert_eq!(
            inspector.observe(direction, &empty).command,
            if index < 7 {
                Command::Continue
            } else {
                Command::End
            }
        );
    }
    assert_eq!(
        inspector.observe(Direction::Uplink, &hello(0x1301)).command,
        Command::End
    );
    let mut inspector = Inspector::new();
    let mut wire = Vec::new();
    for _ in 0..4 {
        wire.extend(app(&vec![0; 18000]));
    }
    let mut cursor = 0;
    while cursor < 65536 {
        let end = (cursor + 317).min(65535);
        if end == cursor {
            break;
        }
        let decision = inspector.observe(Direction::Uplink, &wire[cursor..end]);
        assert_eq!(decision.command, Command::Continue);
        cursor += decision.consumed;
    }
    assert_eq!(cursor, 65535);
    assert_eq!(
        inspector
            .observe(Direction::Uplink, &wire[cursor..cursor + 1])
            .command,
        Command::End
    );
    assert_eq!(
        inspector
            .observe(Direction::Downlink, &hello(0x1301))
            .command,
        Command::End
    );
}

#[test]
fn inspector_partial_headers_reserve_shared_record_budget() {
    let mut inspector = Inspector::new();
    // 第八条头尚未完整时，另一方向不得再开启第九条。
    for _ in 0..7 {
        assert_eq!(
            inspector
                .observe(Direction::Uplink, &record(20, &[]))
                .command,
            Command::Continue
        );
    }
    assert_eq!(
        inspector.observe(Direction::Uplink, &[23]).command,
        Command::Continue
    );
    assert_eq!(
        inspector.observe(Direction::Downlink, &[22]).command,
        Command::End
    );
}

#[test]
fn inspector_eighth_complete_record_can_still_choose_direct() {
    let mut inspector = Inspector::new();
    inspector.observe(Direction::Downlink, &hello(0x1301));
    for _ in 0..6 {
        assert_eq!(
            inspector
                .observe(Direction::Uplink, &record(20, &[1]))
                .command,
            Command::Continue
        );
    }
    let application = app(b"last permitted record");
    for (index, byte) in application.iter().enumerate() {
        assert_eq!(
            inspector.observe(Direction::Downlink, &[*byte]).command,
            if index + 1 == application.len() {
                Command::Direct
            } else {
                Command::Continue
            }
        );
    }
}

#[test]
fn inspector_zero_records_unknown_handshakes_and_bad_hello_vectors() {
    let mut inspector = Inspector::new();
    inspector.observe(Direction::Downlink, &hello(0x1301));
    assert_eq!(
        inspector.observe(Direction::Downlink, &app(&[])).command,
        Command::Direct
    );
    let mut inspector = Inspector::new();
    // 非 ServerHello 的握手跨片正确跳过，再解析真正 ServerHello。
    let mut messages = vec![11, 0, 0, 2, 1, 2, 0, 0, 0, 0];
    messages.extend(hello_message(0x1301, Some([3, 4])));
    assert_eq!(
        observe_all(
            &mut inspector,
            Direction::Downlink,
            &record(22, &messages),
            1
        ),
        Command::Continue
    );
    assert_eq!(
        inspector.observe(Direction::Downlink, &app(b"x")).command,
        Command::Direct
    );
    for body in [vec![], vec![3, 3], vec![0; 60]] {
        let mut message = vec![2, 0, 0, body.len() as u8];
        message.extend(body);
        let mut inspector = Inspector::new();
        assert_eq!(
            observe_all(
                &mut inspector,
                Direction::Downlink,
                &record(22, &message),
                1
            ),
            Command::End
        );
    }
    let mut inspector = Inspector::new();
    assert_eq!(
        inspector
            .observe(Direction::Downlink, &record(22, &[2, 1, 0, 0]))
            .command,
        Command::End
    );
}
