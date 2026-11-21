// 被两个AEAD模块的私有测试模块include；不修改mod.rs、不暴露生产注入接口。
use crate::config::{ReplayAttackPolicy, ServerType};
use std::task::Waker;

struct ControlledIo {
    input: Vec<u8>,
    position: usize,
    output: Vec<u8>,
    reads: usize,
    writes: usize,
    alternate_pending: bool,
    read_pending: bool,
    write_pending: bool,
    fail_write: bool,
}

impl ControlledIo {
    fn new(input: &[u8], alternate_pending: bool) -> Self {
        Self {
            input: input.to_vec(),
            position: 0,
            output: Vec::new(),
            reads: 0,
            writes: 0,
            alternate_pending,
            read_pending: alternate_pending,
            write_pending: alternate_pending,
            fail_write: false,
        }
    }
}

impl AsyncRead for ControlledIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads += 1;
        if self.read_pending {
            self.read_pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.read_pending = self.alternate_pending;
        let n = buf.remaining().min(self.input.len() - self.position);
        buf.put_slice(&self.input[self.position..self.position + n]);
        self.position += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ControlledIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes += 1;
        if self.fail_write {
            return Poll::Ready(Err(io::Error::other("injected write failure")));
        }
        if self.write_pending {
            self.write_pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.write_pending = self.alternate_pending;
        let n = buf.len().min(3); // 强制部分写，Pending重试不得再次加密/计数。
        self.output.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn finish_write(
    writer: &mut EncryptedWriter,
    io: &mut ControlledIo,
    data: &[u8],
) -> io::Result<usize> {
    let mut cx = task::Context::from_waker(Waker::noop());
    for _ in 0..4096 {
        if let Poll::Ready(result) = writer.poll_write_encrypted(&mut cx, io, data) {
            return result;
        }
    }
    panic!("write poll次数超出有限测试上界");
}

fn finish_read(
    reader: &mut DecryptedReader,
    io: &mut ControlledIo,
    output: &mut [u8],
) -> ProtocolResult<usize> {
    let mut context = Context::new(ServerType::Server);
    context.set_replay_attack_policy(ReplayAttackPolicy::Ignore);
    let mut cx = task::Context::from_waker(Waker::noop());
    let mut buf = ReadBuf::new(output);
    for _ in 0..4096 {
        if let Poll::Ready(result) = reader.poll_read_decrypted(&mut cx, &context, io, &mut buf) {
            return result.map(|()| buf.filled().len());
        }
    }
    panic!("read poll次数超出有限测试上界");
}

fn encrypted_chunks(chunks: &[&[u8]]) -> Vec<u8> {
    let mut writer = new_writer();
    let mut io = ControlledIo::new(&[], false);
    for chunk in chunks {
        assert_eq!(
            finish_write(&mut writer, &mut io, chunk).unwrap(),
            chunk.len()
        );
    }
    io.output
}

#[test]
fn aead_budget_writer_counts_actual_operations_once_across_pending_and_partial_writes() {
    let mut writer = new_writer();
    writer.budget = AeadBudget::with_remaining(4);
    let mut io = ControlledIo::new(&[], true);
    let mut cx = task::Context::from_waker(Waker::noop());
    assert!(
        writer
            .poll_write_encrypted(&mut cx, &mut io, b"one")
            .is_pending()
    );
    assert_eq!(writer.budget.remaining(), 2); // 固定头/长度与载荷各一次。
    assert_eq!(finish_write(&mut writer, &mut io, b"one").unwrap(), 3);
    assert_eq!(writer.budget.remaining(), 2);
    assert_eq!(finish_write(&mut writer, &mut io, b"two").unwrap(), 3);
    assert_eq!(writer.budget.remaining(), 0);
    let sent = io.output.clone();
    let calls = io.writes;
    for _ in 0..3 {
        assert!(finish_write(&mut writer, &mut io, b"blocked").is_err());
        assert_eq!(io.output, sent);
        assert_eq!(io.writes, calls);
        assert_eq!(writer.budget.remaining(), 0);
    }
}

#[test]
fn aead_budget_writer_incomplete_pair_is_terminal_and_emits_nothing() {
    for remaining in [0, 1] {
        let mut writer = new_writer();
        writer.budget = AeadBudget::with_remaining(remaining);
        let mut io = ControlledIo::new(&[], false);
        assert!(finish_write(&mut writer, &mut io, b"blocked").is_err());
        assert_eq!(writer.budget.remaining(), 0);
        assert_eq!(io.writes, 0);
        assert!(io.output.is_empty());
        assert!(writer.buffer.is_empty());
        for _ in 0..2 {
            assert!(finish_write(&mut writer, &mut io, b"blocked").is_err());
            assert_eq!(io.writes, 0);
        }
    }
}

#[test]
fn aead_budget_writer_io_failure_is_terminal_even_with_unspent_budget() {
    let mut writer = new_writer();
    writer.budget = AeadBudget::with_remaining(8);
    let mut io = ControlledIo::new(&[], false);
    io.fail_write = true;
    assert!(finish_write(&mut writer, &mut io, b"blocked").is_err());
    assert_eq!(writer.budget.remaining(), 6);
    assert_eq!(io.writes, 1);
    io.fail_write = false;
    assert!(finish_write(&mut writer, &mut io, b"blocked").is_err());
    assert_eq!(writer.budget.remaining(), 6);
    assert_eq!(io.writes, 1);
    assert!(io.output.is_empty());
}

#[test]
fn aead_budget_writer_error_after_partial_output_never_resumes_output() {
    let mut writer = new_writer();
    writer.budget = AeadBudget::with_remaining(8);
    let mut io = ControlledIo::new(&[], true);
    let mut cx = task::Context::from_waker(Waker::noop());
    assert!(
        writer
            .poll_write_encrypted(&mut cx, &mut io, b"blocked")
            .is_pending()
    );
    assert!(
        writer
            .poll_write_encrypted(&mut cx, &mut io, b"blocked")
            .is_pending()
    );
    assert_eq!(io.output.len(), 3);
    io.fail_write = true;
    assert!(finish_write(&mut writer, &mut io, b"blocked").is_err());
    let sent = io.output.clone();
    let writes = io.writes;
    io.fail_write = false;
    assert!(finish_write(&mut writer, &mut io, b"blocked").is_err());
    assert_eq!(io.output, sent);
    assert_eq!(io.writes, writes);
    assert_eq!(writer.budget.remaining(), 6);
}

#[test]
fn aead_budget_reader_later_length_cannot_release_unbudgeted_data() {
    let wire = encrypted_chunks(&[b"one", b"hidden"]);
    let mut reader = new_reader();
    reader.budget = AeadBudget::with_remaining(3);
    let mut io = ControlledIo::new(&wire, true);
    let mut first = [0; 3];
    assert_eq!(finish_read(&mut reader, &mut io, &mut first).unwrap(), 3);
    assert_eq!(first, *b"one");
    assert_eq!(reader.budget.remaining(), 1);
    let mut blocked = [0xaa; 16];
    assert!(finish_read(&mut reader, &mut io, &mut blocked).is_err());
    assert_eq!(reader.budget.remaining(), 0);
    assert_eq!(blocked, [0xaa; 16]);
    let calls = io.reads;
    assert!(finish_read(&mut reader, &mut io, &mut blocked).is_err());
    assert_eq!(io.reads, calls);
}

#[test]
fn aead_budget_reader_header_and_data_pending_do_not_spend_or_repeat_operations() {
    let wire = encrypted_chunks(&[b"one", b"two"]);
    let mut reader = new_reader();
    reader.budget = AeadBudget::with_remaining(4);
    let mut io = ControlledIo::new(&wire, true);
    let mut context = Context::new(ServerType::Server);
    context.set_replay_attack_policy(ReplayAttackPolicy::Ignore);
    let mut cx = task::Context::from_waker(Waker::noop());
    let mut output = [0; 3];
    let mut buf = ReadBuf::new(&mut output);
    assert!(
        reader
            .poll_read_decrypted(&mut cx, &context, &mut io, &mut buf)
            .is_pending()
    );
    assert_eq!(reader.budget.remaining(), 4); // 包括2022首固定头：Pending不消费。
    let mut saw_first_operation = false;
    for _ in 0..32 {
        let result = reader.poll_read_decrypted(&mut cx, &context, &mut io, &mut buf);
        if result.is_pending() && reader.budget.remaining() == 3 {
            saw_first_operation = true; // 固定头/长度已认证，载荷read仍Pending。
            break;
        }
        assert!(result.is_pending());
    }
    assert!(saw_first_operation);
    assert_eq!(finish_read(&mut reader, &mut io, &mut output).unwrap(), 3);
    assert_eq!(output, *b"one");
    assert_eq!(reader.budget.remaining(), 2);
    // 耗尽后仍可交付最后一次成功认证而已缓冲的明文，不再执行密码操作。
    let mut byte = [0; 1];
    assert_eq!(finish_read(&mut reader, &mut io, &mut byte).unwrap(), 1);
    assert_eq!(byte, *b"t");
    assert_eq!(reader.budget.remaining(), 0);
    let mut rest = [0; 2];
    assert_eq!(finish_read(&mut reader, &mut io, &mut rest).unwrap(), 2);
    assert_eq!(rest, *b"wo");
    let calls = io.reads;
    for _ in 0..3 {
        assert!(finish_read(&mut reader, &mut io, &mut output).is_err());
        assert_eq!(io.reads, calls);
        assert_eq!(reader.budget.remaining(), 0);
        assert!(reader.cipher.is_none());
    }
}

#[test]
fn aead_budget_reader_one_operation_cannot_authenticate_or_release_payload() {
    let wire = encrypted_chunks(&[b"hidden"]);
    for remaining in [0, 1] {
        let mut reader = new_reader();
        reader.budget = AeadBudget::with_remaining(remaining);
        let mut io = ControlledIo::new(&wire, true);
        let mut output = [0xaa; 16];
        assert!(finish_read(&mut reader, &mut io, &mut output).is_err());
        assert_eq!(reader.budget.remaining(), 0);
        assert_eq!(output, [0xaa; 16]);
        assert!(reader.cipher.is_none());
        let calls = io.reads;
        let position = io.position;
        assert!(finish_read(&mut reader, &mut io, &mut output).is_err());
        assert_eq!((io.reads, io.position), (calls, position));
    }
}

#[test]
fn aead_budget_reader_bad_header_or_payload_tag_spends_once_and_is_terminal() {
    for corrupt_at in [
        INITIAL_HEADER_LEN - 1,
        encrypted_chunks(&[b"hidden"]).len() - 1,
    ] {
        let mut wire = encrypted_chunks(&[b"hidden"]);
        wire[corrupt_at] ^= 1;
        let mut reader = new_reader();
        reader.budget = AeadBudget::with_remaining(8);
        let mut io = ControlledIo::new(&wire, true);
        let mut output = [0xaa; 16];
        assert!(finish_read(&mut reader, &mut io, &mut output).is_err());
        let expected = if corrupt_at == INITIAL_HEADER_LEN - 1 {
            7
        } else {
            6
        };
        assert_eq!(reader.budget.remaining(), expected);
        assert_eq!(output, [0xaa; 16]);
        let calls = io.reads;
        assert!(finish_read(&mut reader, &mut io, &mut output).is_err());
        assert_eq!(io.reads, calls);
        assert_eq!(reader.budget.remaining(), expected);
        assert!(reader.cipher.is_none());
    }
}
