//! 有界原始 ClientHello 预读；deadline 由调用方在整个握手链外层统一施加。
use std::{
    collections::HashSet,
    io,
    ops::Range,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

pub(crate) const MAX_RECORD: usize = 18_432;
pub(crate) const MAX_HELLO: usize = 65_536;
pub(crate) const MAX_PREFIX: usize = 131_072;
pub(crate) const MAX_RECORDS: usize = 32;
pub(crate) const HYBRID: u16 = 0x11ec;
pub(crate) const X25519: u16 = 0x001d;

// 不派生 Debug：完整 CH、SID 和 shortID 不属于可公开的诊断。
pub(crate) struct Hello {
    pub wire_prefix: Vec<u8>,
    pub raw_ch: Vec<u8>,
    pub random: [u8; 32],
    pub session_id: Range<usize>,
    pub sni: Option<String>,
    pub hybrid: Option<Vec<u8>>,
    pub x25519: Option<[u8; 32]>,
    pub cipher_suites: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub supported_versions: Vec<u16>,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "REALITY ClientHello 结构无效或超限",
    )
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(invalid)?;
        let out = self.data.get(self.pos..end).ok_or_else(invalid)?;
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> io::Result<usize> {
        Ok(usize::from(self.take(1)?[0]))
    }
    fn u16(&mut self) -> io::Result<usize> {
        let b = self.take(2)?;
        Ok(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }
    fn vector8(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u8()?;
        self.take(n)
    }
    fn vector16(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u16()?;
        self.take(n)
    }
    fn done(&self) -> io::Result<()> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

fn words(bytes: &[u8]) -> io::Result<Vec<u16>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return Err(invalid());
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|p| u16::from_be_bytes([p[0], p[1]]))
        .collect())
}

pub(crate) async fn read<S: AsyncRead + Unpin>(io: &mut S) -> io::Result<Hello> {
    let mut wire_prefix = Vec::new();
    let mut raw_ch = Vec::new();
    let mut hello_len = None;
    for _ in 0..MAX_RECORDS {
        let mut header = [0; 5];
        io.read_exact(&mut header).await?;
        if header[0] != 22 || header[1] != 3 || !(1..=3).contains(&header[2]) {
            return Err(invalid());
        }
        let n = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if n > MAX_RECORD
            || wire_prefix
                .len()
                .checked_add(5)
                .and_then(|v| v.checked_add(n))
                .is_none_or(|v| v > MAX_PREFIX)
        {
            return Err(invalid());
        }
        wire_prefix.extend_from_slice(&header);
        let mut remaining = n;
        // 先收齐四字节握手头，校验声明长度后才读取本 record 剩余部分。
        if raw_ch.len() < 4 {
            let count = (4 - raw_ch.len()).min(remaining);
            let start = wire_prefix.len();
            wire_prefix.resize(start + count, 0);
            io.read_exact(&mut wire_prefix[start..]).await?;
            raw_ch.extend_from_slice(&wire_prefix[start..]);
            remaining -= count;
            if raw_ch.len() == 4 {
                let body = (usize::from(raw_ch[1]) << 16)
                    | (usize::from(raw_ch[2]) << 8)
                    | usize::from(raw_ch[3]);
                let total = body.checked_add(4).ok_or_else(invalid)?;
                if raw_ch[0] != 1 || total > MAX_HELLO {
                    return Err(invalid());
                }
                hello_len = Some(total);
            }
        }
        let start = wire_prefix.len();
        wire_prefix.resize(start + remaining, 0);
        io.read_exact(&mut wire_prefix[start..]).await?;
        if let Some(total) = hello_len {
            let count = total
                .checked_sub(raw_ch.len())
                .ok_or_else(invalid)?
                .min(remaining);
            raw_ch.extend_from_slice(&wire_prefix[start..start + count]);
            if raw_ch.len() == total {
                return parse(raw_ch, wire_prefix);
            }
        }
    }
    Err(invalid())
}

fn parse(raw_ch: Vec<u8>, wire_prefix: Vec<u8>) -> io::Result<Hello> {
    let mut c = Cursor::new(&raw_ch);
    let header = c.take(4)?;
    let declared =
        (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
    if header[0] != 1 || declared.checked_add(4) != Some(raw_ch.len()) || raw_ch.len() > MAX_HELLO {
        return Err(invalid());
    }
    let legacy_version = c.take(2)?;
    if legacy_version[0] != 3 || !(1..=3).contains(&legacy_version[1]) {
        return Err(invalid());
    }
    let random = c.take(32)?.try_into().map_err(|_| invalid())?;
    let sid_len = c.u8()?;
    if sid_len > 32 {
        return Err(invalid());
    }
    let sid_start = c.pos;
    c.take(sid_len)?;
    let session_id = sid_start..c.pos;
    let cipher_suites = words(c.vector16()?)?;
    let compression = c.vector8()?;
    if compression.is_empty() || !compression.contains(&0) {
        return Err(invalid());
    }
    let mut sni = None;
    let mut hybrid = None;
    let mut x25519 = None;
    let mut supported_groups = Vec::new();
    let mut supported_versions = Vec::new();
    // TLS1.2 的普通 CH 可以没有 extensions；它不能认证，但可以固定目标回落。
    if c.pos < raw_ch.len() {
        let mut extensions = Cursor::new(c.vector16()?);
        let mut seen = HashSet::new();
        let mut saw_plain = false;
        while extensions.pos < extensions.data.len() {
            let kind = extensions.u16()?;
            if !seen.insert(kind) {
                return Err(invalid());
            }
            let data = extensions.vector16()?;
            let mut e = Cursor::new(data);
            match kind {
                0 => {
                    let mut names = Cursor::new(e.vector16()?);
                    if names.data.is_empty() {
                        return Err(invalid());
                    }
                    let mut name_kinds = HashSet::new();
                    while names.pos < names.data.len() {
                        let kind = names.u8()?;
                        if !name_kinds.insert(kind) {
                            return Err(invalid());
                        }
                        let name = names.vector16()?;
                        if name.is_empty() {
                            return Err(invalid());
                        }
                        if kind == 0 {
                            if !name.is_ascii() || name.contains(&0) {
                                return Err(invalid());
                            }
                            sni = Some(String::from_utf8(name.to_vec()).map_err(|_| invalid())?);
                        }
                    }
                    e.done()?;
                }
                10 => {
                    supported_groups = words(e.vector16()?)?;
                    e.done()?;
                }
                43 => {
                    supported_versions = words(e.vector8()?)?;
                    e.done()?;
                }
                13 => {
                    words(e.vector16()?)?;
                    e.done()?;
                }
                // 只声明 PSK 模式不是提出 PSK，但它自身的向量仍须合法。
                45 => {
                    if e.vector8()?.is_empty() {
                        return Err(invalid());
                    }
                    e.done()?;
                }
                // 实际 PSK 和 early_data 不允许。
                41 | 42 => return Err(invalid()),
                51 => {
                    let mut shares = Cursor::new(e.vector16()?);
                    let mut groups = HashSet::new();
                    while shares.pos < shares.data.len() {
                        let group = shares.u16()? as u16;
                        if !groups.insert(group) {
                            return Err(invalid());
                        }
                        let share = shares.vector16()?;
                        if share.is_empty() {
                            return Err(invalid());
                        }
                        match group {
                            HYBRID => {
                                if share.len() != 1216 || saw_plain {
                                    return Err(invalid());
                                }
                                hybrid = Some(share.to_vec());
                            }
                            X25519 => {
                                if share.len() != 32 {
                                    return Err(invalid());
                                }
                                saw_plain = true;
                                x25519 = Some(share.try_into().map_err(|_| invalid())?);
                            }
                            _ => {}
                        }
                    }
                    e.done()?;
                }
                _ => {}
            }
        }
    }
    c.done()?;
    if supported_versions.contains(&0x0304) && (compression != [0] || legacy_version != [3, 3]) {
        return Err(invalid());
    }
    Ok(Hello {
        wire_prefix,
        raw_ch,
        random,
        session_id,
        sni,
        hybrid,
        x25519,
        cipher_suites,
        supported_groups,
        supported_versions,
    })
}

/// prefix 只有一个游标/所有者；读尽前不 poll 底层读取，写操作直接委托。
pub(crate) struct PrefixIo<S> {
    prefix: Vec<u8>,
    offset: usize,
    io: S,
}
impl<S> PrefixIo<S> {
    pub(crate) fn new(prefix: Vec<u8>, io: S) -> Self {
        Self {
            prefix,
            offset: 0,
            io,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for PrefixIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let n = buf.remaining().min(this.prefix.len() - this.offset);
            buf.put_slice(&this.prefix[this.offset..this.offset + n]);
            this.offset += n;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut this.io).poll_read(cx, buf)
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    // 独立的测试端线格式构造，不调用生产解析/认证编码。
    fn ext(kind: u16, data: &[u8]) -> Vec<u8> {
        [
            kind.to_be_bytes().to_vec(),
            (data.len() as u16).to_be_bytes().to_vec(),
            data.to_vec(),
        ]
        .concat()
    }
    fn vector(data: &[u8]) -> Vec<u8> {
        [(data.len() as u16).to_be_bytes().to_vec(), data.to_vec()].concat()
    }
    fn shares(groups: &[(u16, usize)]) -> Vec<u8> {
        vector(
            &groups
                .iter()
                .flat_map(|(group, n)| {
                    [group.to_be_bytes().to_vec(), vector(&vec![7; *n])].concat()
                })
                .collect::<Vec<_>>(),
        )
    }
    fn ch(extensions: &[u8]) -> Vec<u8> {
        let b = [
            vec![3, 3],
            vec![9; 32],
            vec![32],
            vec![0; 32],
            vec![0, 2, 0x13, 1, 1, 0],
            vector(extensions),
        ]
        .concat();
        [
            vec![
                1,
                ((b.len() >> 16) & 255) as u8,
                ((b.len() >> 8) & 255) as u8,
                (b.len() & 255) as u8,
            ],
            b,
        ]
        .concat()
    }
    fn normal_ext() -> Vec<u8> {
        [
            ext(0, &vector(&[vec![0], vector(b"example.test")].concat())),
            ext(43, &[2, 3, 4]),
            ext(51, &shares(&[(HYBRID, 1216), (X25519, 32)])),
        ]
        .concat()
    }
    fn record(data: &[u8]) -> Vec<u8> {
        [vec![22, 3, 1], vector(data)].concat()
    }
    async fn read_bytes(mut bytes: &[u8]) -> io::Result<Hello> {
        read(&mut bytes).await
    }

    #[tokio::test]
    async fn fragmented_single_byte_and_exact_tail_replay() {
        let raw = ch(&normal_ext());
        let mut split = Vec::new();
        for part in raw.chunks(raw.len().div_ceil(31)) {
            split.extend(record(part));
        }
        let h = read_bytes(&split).await.unwrap();
        assert_eq!(h.raw_ch, raw);
        assert_eq!(h.wire_prefix, split);
        assert_eq!(h.sni.as_deref(), Some("example.test"));
        assert_eq!(h.session_id, 39..71);
        assert_eq!(h.supported_versions, vec![0x0304]);
        assert_eq!(h.hybrid.as_ref().unwrap().len(), 1216);
        assert_eq!(h.x25519, Some([7; 32]));
        let mut last = raw.clone();
        last.extend_from_slice(b"record-tail");
        let wire = record(&last);
        let (mut sender, mut receiver) = tokio::io::duplex(1);
        let send = tokio::spawn(async move {
            for byte in wire {
                sender.write_all(&[byte]).await.unwrap();
            }
            sender.write_all(b"unread-next-record").await.unwrap();
        });
        let h = read(&mut receiver).await.unwrap();
        assert_eq!(h.raw_ch, raw);
        assert_eq!(h.wire_prefix, record(&last));
        let mut io = PrefixIo::new(h.wire_prefix, receiver);
        let mut replayed = Vec::new();
        io.read_to_end(&mut replayed).await.unwrap();
        send.await.unwrap();
        assert_eq!(
            replayed,
            [record(&last), b"unread-next-record".to_vec()].concat()
        );
    }

    #[tokio::test]
    async fn every_truncation_and_all_handshake_truncations_reject() {
        let raw = ch(&normal_ext());
        let wire = record(&raw);
        for n in 0..wire.len() {
            assert!(read_bytes(&wire[..n]).await.is_err(), "wire {n}");
        }
        // 调整握手外层长度，确保各内层字段仍会独立发现截断。
        for n in 4..raw.len() {
            let mut part = raw[..n].to_vec();
            let len = n - 4;
            part[1..4].copy_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
            if n == ch(&[]).len() - 2 {
                // 恰好删去整个可选扩展向量时，是结构合法的普通 TLS1.2 CH。
                let hello = read_bytes(&record(&part)).await.unwrap();
                assert!(hello.hybrid.is_none());
            } else {
                assert!(read_bytes(&record(&part)).await.is_err(), "inner {n}");
            }
        }
    }

    #[tokio::test]
    async fn duplicate_malformed_share_order_and_forbidden_extensions() {
        let good = normal_ext();
        for extra in [
            ext(0, &vector(&[vec![0], vector(b"other.test")].concat())),
            ext(43, &[2, 3, 4]),
            ext(51, &shares(&[(X25519, 32)])),
            ext(41, &[]),
            ext(42, &[]),
        ] {
            assert!(
                read_bytes(&record(&ch(&[good.clone(), extra].concat())))
                    .await
                    .is_err()
            );
        }
        for groups in [
            vec![(HYBRID, 1215)],
            vec![(HYBRID, 1217)],
            vec![(X25519, 31)],
            vec![(X25519, 33)],
            vec![(HYBRID, 1216), (HYBRID, 1216)],
            vec![(HYBRID, 1216), (X25519, 32), (X25519, 32)],
            vec![(X25519, 32), (HYBRID, 1216)],
        ] {
            assert!(
                read_bytes(&record(&ch(&ext(51, &shares(&groups)))))
                    .await
                    .is_err()
            );
        }
        for (kind, data) in [
            (0, vec![0, 4, 0, 0, 2, 1]),
            (43, vec![3, 3, 4, 3]),
            (10, vec![0, 1, 29]),
            (51, vec![0, 4, 0, 29, 0, 32]),
        ] {
            assert!(read_bytes(&record(&ch(&ext(kind, &data)))).await.is_err());
        }
        assert!(read_bytes(&record(&ch(&ext(45, &[1, 1])))).await.is_ok());
        assert!(
            read_bytes(&record(&ch(&ext(51, &shares(&[(X25519, 32)])))))
                .await
                .unwrap()
                .hybrid
                .is_none()
        );
        assert!(
            read_bytes(&record(&ch(&ext(51, &shares(&[(HYBRID, 1216)])))))
                .await
                .unwrap()
                .x25519
                .is_none()
        );
        assert!(read_bytes(&record(&ch(&[]))).await.is_ok());
    }

    #[tokio::test]
    async fn record_handshake_count_total_boundaries_and_no_next_record_pre_read() {
        let raw = ch(&normal_ext());
        let mut wire = record(&raw);
        wire.extend_from_slice(b"unread");
        let mut source = wire.as_slice();
        read(&mut source).await.unwrap();
        assert_eq!(source, b"unread");
        for wire in [
            vec![22, 3, 3, 0x48, 1],
            vec![22, 3, 3, 0, 4, 1, 1, 0, 0],
            vec![23, 3, 3, 0, 0],
            record(&[1, 0, 0, 0]),
        ] {
            assert!(read_bytes(&wire).await.is_err());
        }
        let mut many = record(&[]).repeat(31);
        many.extend(record(&raw));
        assert!(read_bytes(&many).await.is_ok());
        let mut many = record(&[]).repeat(32);
        many.extend(record(&raw));
        assert!(read_bytes(&many).await.is_err());
        // 65536 是完整握手边界，不是 body 长度上限。
        let filler = 65536 - ch(&[]).len() - 4;
        let raw = ch(&ext(65000, &vec![0; filler]));
        assert_eq!(raw.len(), 65536);
        let wire = raw.chunks(MAX_RECORD).flat_map(record).collect::<Vec<_>>();
        assert!(read_bytes(&wire).await.is_ok());
        let mut raw = raw;
        raw[1..4].copy_from_slice(&[0, 255, 253]); // 声明总长 65537
        assert!(read_bytes(&record(&raw[..4])).await.is_err());
        // 最大当前 record 尾部被保存，但不会读下一条 record。
        let raw = ch(&[]);
        let mut body = raw.clone();
        body.resize(MAX_RECORD, 0);
        let h = read_bytes(&record(&body)).await.unwrap();
        assert_eq!(h.wire_prefix.len(), MAX_RECORD + 5);
        assert_eq!(h.raw_ch, raw);
    }

    #[tokio::test]
    async fn absolute_deadline_cancellation_leaves_no_reader_task() {
        let (mut tx, mut rx) = tokio::io::duplex(16);
        tx.write_all(&[22, 3, 3, 0, 10, 1]).await.unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(10);
        assert!(
            tokio::time::timeout_at(deadline, read(&mut rx))
                .await
                .is_err()
        );
        // future 丢弃后无后台消费者；所有后续字节仍归原 socket。
        tx.write_all(b"still-owned").await.unwrap();
        let mut rest = [0; 11];
        rx.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"still-owned");
    }

    #[tokio::test]
    async fn checked_vectors_sid_ranges_and_header_early_reject() {
        let raw = ch(&normal_ext());
        for (offset, bytes) in [
            (38, vec![33]),
            (71, vec![0, 0]),
            (71, vec![0, 1]),
            (75, vec![0]),
            (76, vec![1]),
            (77, vec![255, 255]),
        ] {
            let mut bad = raw.clone();
            bad[offset..offset + bytes.len()].copy_from_slice(&bytes);
            assert!(read_bytes(&record(&bad)).await.is_err(), "offset {offset}");
        }
        for (kind, payload) in [
            (
                0,
                vector(&[vec![0], vector(b"a.test"), vec![0], vector(b"b.test")].concat()),
            ),
            (45, vec![0]),
            (45, vec![2, 1]),
            (13, vec![0, 1, 7]),
        ] {
            assert!(
                read_bytes(&record(&ch(&ext(kind, &payload))))
                    .await
                    .is_err()
            );
        }
        // 声明超长握手后立即拒绝，不等待同 record 的其余声明载荷。
        let (mut tx, mut rx) = tokio::io::duplex(32);
        tx.write_all(&[22, 3, 3, 0, 100, 1, 1, 0, 0]).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), read(&mut rx))
                .await
                .unwrap()
                .is_err()
        );
        let mut short_sid = ch(&[]);
        short_sid.drain(39..71);
        short_sid[38] = 0;
        let len = short_sid.len() - 4;
        short_sid[1..4].copy_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        let hello = read_bytes(&record(&short_sid)).await.unwrap();
        assert_eq!(hello.session_id, 39..39);
        // prefix 总量受更紧的 CH(65536)+当前record尾部(18432)+32*5 上界约束。
        const {
            assert!(MAX_HELLO + MAX_RECORD + MAX_RECORDS * 5 < MAX_PREFIX);
        }
    }

    #[tokio::test]
    async fn cancellation_at_every_record_byte_keeps_unique_socket_owner() {
        let wire = record(&ch(&normal_ext()));
        for n in 0..wire.len() {
            let (mut tx, mut rx) = tokio::io::duplex(wire.len() + 16);
            tx.write_all(&wire[..n]).await.unwrap();
            let mut read_future = Box::pin(read(&mut rx));
            std::future::poll_fn(|cx| {
                assert!(read_future.as_mut().poll(cx).is_pending(), "cancel {n}");
                Poll::Ready(())
            })
            .await;
            drop(read_future);
            tx.write_all(b"after-cancel").await.unwrap();
            tx.shutdown().await.unwrap();
            let mut unread = Vec::new();
            rx.read_to_end(&mut unread).await.unwrap();
            // Tokio 协作预算可能在一次 poll 内先返回 Pending；未读旧字节仍必须
            // 是原输入的后缀，marker 不被取消后的后台读取吞掉。
            assert!(unread.ends_with(b"after-cancel"), "cancel {n}");
            assert!(wire[..n].ends_with(&unread[..unread.len() - 12]));
        }
    }

    #[tokio::test]
    async fn prefix_partial_reads_zero_buffer_and_write_forwarding() {
        let (a, mut b) = tokio::io::duplex(64);
        let mut prefixed = PrefixIo::new(b"prefix".to_vec(), a);
        prefixed.read_exact(&mut []).await.unwrap();
        let mut first = [0; 2];
        prefixed.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"pr");
        b.write_all(b"socket").await.unwrap();
        b.shutdown().await.unwrap();
        let mut rest = Vec::new();
        prefixed.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"efixsocket");
        prefixed.write_all(b"forwarded").await.unwrap();
        prefixed.flush().await.unwrap();
        prefixed.shutdown().await.unwrap();
        let mut written = Vec::new();
        b.read_to_end(&mut written).await.unwrap();
        assert_eq!(written, b"forwarded");
    }
}
