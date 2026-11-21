//! Bounded opt-in TLS1.3 hooks for an externally authenticated REALITY connection.
//!
//! This module does not authenticate REALITY, connect to targets, or relax TLS
//! certificate/CertificateVerify/Finished checks. Each `Config` belongs to one
//! connection. All initial output is withheld until its complete flight is ready.
use alloc::{sync::Arc, vec::Vec};
use core::{fmt, ops::Range};

use crate::common_state::{CommonState, Protocol};
use crate::crypto::SupportedKxGroup;
use crate::msgs::codec::Reader;
use crate::msgs::handshake::{
    ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload, OutboundPlainMessage};
use crate::sign::{CertifiedKey, SigningKey};
use crate::{
    CipherSuite, ContentType, Error, NamedGroup, ProtocolVersion, ServerConfig, SignatureScheme,
    SupportedCipherSuite,
};

/// Maximum retained initial flight, including all record headers.
pub const MAX_FLIGHT_SIZE: usize = 131_072;
/// Maximum TLSInnerPlaintext size, including content type and zero padding.
pub(crate) const MAX_INNER_PLAINTEXT: usize = 16_385;
const MAX_RAW_SH: usize = 2048;
const TAG_LEN: usize = 16;
const MAX_RECORD: usize = 5 + MAX_INNER_PLAINTEXT + TAG_LEN;
const MAX_CERT_CHAIN: usize = 65_536;

pub(crate) fn invalid() -> Error {
    Error::General("incompatible REALITY TLS template or flight".into())
}

/// A per-connection certificate resolver called after final raw ServerHello
/// construction and before Certificate encoding (including optional ML-DSA).
///
/// The returned key must be the same `Arc<dyn SigningKey>` as the initial
/// `ServerConfig::cert_resolver` key; its certificate must contain that key's
/// SPKI. The callback cannot change negotiation or access traffic secrets.
pub trait ResolvesCertificate: fmt::Debug + Send + Sync {
    /// Resolve the certificate using the exact outgoing handshake encoding,
    /// including its four-byte handshake header, but no record header.
    fn resolve(&self, final_raw_sh: &[u8]) -> Result<Arc<CertifiedKey>, Error>;
}

/// One of the two fixed D7 initial-flight record layouts.
#[derive(Clone, Debug)]
pub struct RecordPlan {
    sh_total: usize,
    ccs_total: usize,
    encrypted: Vec<usize>,
    empty_app: Option<usize>,
}

impl RecordPlan {
    /// Build a plan from total record lengths (including the five-byte header).
    /// `ccs_total` is 6, or 0 for an explicitly absent CCS. A first encrypted
    /// length greater than 512 requires one aggregated record; otherwise exactly
    /// four records contain EE, Certificate, CertificateVerify and Finished.
    /// The optional last slot carries zero application plaintext, never a ticket.
    pub fn new(
        sh_total: usize,
        ccs_total: usize,
        encrypted: Vec<usize>,
        empty_app: Option<usize>,
    ) -> Result<Self, Error> {
        if !(5..=MAX_RAW_SH + 5).contains(&sh_total) || !matches!(ccs_total, 0 | 6) {
            return Err(invalid());
        }
        let Some(first) = encrypted.first() else {
            return Err(invalid());
        };
        if encrypted.len() != if *first > 512 { 1 } else { 4 } {
            return Err(invalid());
        }
        let mut total = sh_total
            .checked_add(ccs_total)
            .ok_or_else(invalid)?;
        for len in encrypted.iter().chain(empty_app.iter()) {
            if !(5 + 1 + TAG_LEN..=MAX_RECORD).contains(len) {
                return Err(invalid());
            }
            total = total
                .checked_add(*len)
                .ok_or_else(invalid)?;
        }
        if total > MAX_FLIGHT_SIZE {
            return Err(invalid());
        }
        Ok(Self {
            sh_total,
            ccs_total,
            encrypted,
            empty_app,
        })
    }

    fn padding(&self, payload_len: usize, total: usize) -> Result<usize, Error> {
        // TLSPlaintext.fragment <= 2^14; TLSInnerPlaintext <= 2^14 + 1.
        if payload_len > 16_384 {
            return Err(invalid());
        }
        // 尽力模仿目标记录总长；目标槽位小于本地消息时使用自然长度而不是
        // 回退。Xray 的 REALITY 也不要求本地 flight 与目标逐 record 等长。
        let padding = total
            .checked_sub(5 + 1 + TAG_LEN)
            .and_then(|space| space.checked_sub(payload_len))
            .unwrap_or(0);
        if payload_len + 1 + padding > MAX_INNER_PLAINTEXT {
            return Err(invalid());
        }
        Ok(padding)
    }

    fn fragments<'a>(&self, body: &'a [u8]) -> Result<Vec<(&'a [u8], usize)>, Error> {
        if body.len() > MAX_FLIGHT_SIZE {
            return Err(invalid());
        }
        let mut cursor = Cursor::new(body);
        let mut messages = Vec::with_capacity(4);
        for typ in [8, 11, 15, 20] {
            let start = cursor.pos;
            if cursor.u8()? != typ {
                return Err(invalid());
            }
            let len = cursor.take(3)?;
            let len =
                (usize::from(len[0]) << 16) | (usize::from(len[1]) << 8) | usize::from(len[2]);
            cursor.take(len)?;
            messages.push(&body[start..cursor.pos]);
        }
        if !cursor.empty() {
            return Err(invalid());
        }
        if self.encrypted.len() == 1 {
            messages = alloc::vec![body];
        }
        messages
            .into_iter()
            .zip(self.encrypted.iter().copied())
            .map(|(message, total)| {
                self.padding(message.len(), total)
                    .map(|padding| (message, padding))
            })
            .collect()
    }
}

/// Validated, immutable template and bounded record policy for one connection.
/// Ordinary TLS configurations leave `ServerConfig::reality` as `None`.
pub struct Config {
    raw_server_hello: Vec<u8>,
    template: Template,
    record_plan: RecordPlan,
    certificate_resolver: Arc<dyn ResolvesCertificate>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("reality::Config")
            .field("suite", &self.template.suite)
            .field("group", &self.template.group)
            .field("record_plan", &self.record_plan)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// Validate the raw target SH and record plan. Client offers and provider
    /// support are checked again against the actual ClientHello inside rustls.
    pub fn new(
        raw_server_hello: Vec<u8>,
        record_plan: RecordPlan,
        certificate_resolver: Arc<dyn ResolvesCertificate>,
    ) -> Result<Self, Error> {
        let template = Template::parse(&raw_server_hello)?;
        if record_plan.sh_total != raw_server_hello.len() + 5 {
            return Err(invalid());
        }
        Ok(Self {
            raw_server_hello,
            template,
            record_plan,
            certificate_resolver,
        })
    }

    /// Target-selected TLS1.3 cipher suite.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.template.suite
    }
    /// Target-selected X25519 or X25519MLKEM768 group.
    pub fn named_group(&self) -> NamedGroup {
        self.template.group
    }

    pub(crate) fn validate_config(config: &ServerConfig, protocol: Protocol) -> Result<(), Error> {
        if protocol != Protocol::Tcp
            || config.max_early_data_size != 0
            || config.send_half_rtt_data
            || config.send_tls13_tickets != 0
            || config.max_tls13_tickets != 0
            || config.ticketer.enabled()
            || config.enable_secret_extraction
            || config.verifier.offer_client_auth()
            || !config.cert_compressors.is_empty()
            || config
                .cert_resolver
                .only_raw_public_keys()
            || !config.supports_version(ProtocolVersion::TLSv1_3, protocol)
            || config.supports_version(ProtocolVersion::TLSv1_2, protocol)
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn select(
        &self,
        config: &ServerConfig,
        ch: &ClientHelloPayload,
        version: ProtocolVersion,
        protocol: Protocol,
    ) -> Result<(SupportedCipherSuite, &'static dyn SupportedKxGroup), Error> {
        Self::validate_config(config, protocol)?;
        if version != ProtocolVersion::TLSv1_3
            || ch.session_id.as_ref() != self.template.sid
            || ch.preshared_key_offer.is_some()
            || ch.early_data_request.is_some()
            || !ch
                .supported_versions
                .as_ref()
                .is_some_and(|v| v.tls13)
            || !ch
                .cipher_suites
                .contains(&self.template.suite)
            || !ch
                .named_groups
                .as_ref()
                .is_some_and(|groups| groups.contains(&self.template.group))
            || ch.has_keyshare_extension_with_duplicates()
            || !ch
                .key_shares
                .as_ref()
                .is_some_and(|shares| {
                    shares.iter().any(|share| {
                        share.group == self.template.group
                            && share.payload.0.len()
                                == match share.group {
                                    NamedGroup::X25519 => 32,
                                    NamedGroup::X25519MLKEM768 => 1216,
                                    _ => 0,
                                }
                    })
                })
        {
            return Err(invalid());
        }
        let suite = config
            .provider
            .cipher_suites
            .iter()
            .copied()
            .find(|suite| suite.suite() == self.template.suite && suite.tls13().is_some())
            .ok_or_else(invalid)?;
        let group = config
            .provider
            .kx_groups
            .iter()
            .copied()
            .find(|group| group.name() == self.template.group && group.usable_for_version(version))
            .ok_or_else(invalid)?;
        Ok((suite, group))
    }

    pub(crate) fn final_hello(
        &self,
        suite: CipherSuite,
        group: NamedGroup,
        sid: &SessionId,
        local_share: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if suite != self.template.suite
            || group != self.template.group
            || sid.as_ref() != self.template.sid
            || local_share.len() != self.template.share.len()
        {
            return Err(invalid());
        }
        let mut raw = self.raw_server_hello.clone();
        raw[self.template.share.clone()].copy_from_slice(local_share);
        let checked = Template::parse(&raw)?;
        if checked.sid != self.template.sid || checked.suite != suite || checked.group != group {
            return Err(invalid());
        }
        Ok(raw)
    }

    pub(crate) fn resolve(
        &self,
        raw: &[u8],
        original_key: &dyn SigningKey,
        _schemes: &[SignatureScheme],
    ) -> Result<Arc<CertifiedKey>, Error> {
        let key = self.certificate_resolver.resolve(raw)?;
        let total = key
            .cert
            .iter()
            .try_fold(0usize, |total, cert| total.checked_add(cert.len()))
            .ok_or_else(invalid)?;
        if key.cert.is_empty()
            || key.cert.len() > 8
            || total > MAX_CERT_CHAIN
            || key.ocsp.is_some()
            || !core::ptr::eq::<dyn SigningKey>(&*key.key, original_key)
            || key.key.public_key() != original_key.public_key()
            // REALITY 固定使用 Ed25519 临时证书；与 Xray 一致，即使客户端未在
            // signature_algorithms 中声明 Ed25519，服务端仍以 Ed25519 完成
            // CertificateVerify。这里不能按普通 TLS 的客户端套件列表拒绝。
            || key.key.algorithm() != crate::SignatureAlgorithm::ED25519
        {
            return Err(invalid());
        }
        key.keys_match()?;
        Ok(key)
    }

    pub(crate) fn finish_flight(
        &self,
        common: &mut CommonState,
        raw_sh: &[u8],
        body: &[u8],
    ) -> Result<Vec<Vec<u8>>, Error> {
        if raw_sh.len() + 5 != self.record_plan.sh_total {
            return Err(invalid());
        }
        let fragments = self.record_plan.fragments(body)?;
        // Preflight every length and provider capability before invoking any Seal.
        for (payload, padding) in &fragments {
            common
                .record_layer
                .check_reality_padding(payload.len(), *padding)?;
        }
        if let Some(total) = self.record_plan.empty_app {
            self.record_plan.padding(0, total)?;
        }
        let mut records = Vec::with_capacity(7);
        records.push(
            OutboundPlainMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: raw_sh.into(),
            }
            .to_unencrypted_opaque()
            .encode(),
        );
        if self.record_plan.ccs_total == 6 {
            records.push(alloc::vec![20, 3, 3, 0, 1, 1]);
        }
        for (payload, padding) in fragments {
            records.push(
                common
                    .record_layer
                    .encrypt_reality(
                        OutboundPlainMessage {
                            typ: ContentType::Handshake,
                            version: ProtocolVersion::TLSv1_3,
                            payload: payload.into(),
                        },
                        padding,
                    )?
                    .encode(),
            );
        }
        Ok(records)
    }

    pub(crate) fn finish_application_slot(
        &self,
        common: &mut CommonState,
        records: &mut Vec<Vec<u8>>,
    ) -> Result<(), Error> {
        if let Some(total) = self.record_plan.empty_app {
            let padding = self.record_plan.padding(0, total)?;
            records.push(
                common
                    .record_layer
                    .encrypt_reality(
                        OutboundPlainMessage {
                            typ: ContentType::ApplicationData,
                            version: ProtocolVersion::TLSv1_3,
                            payload: (&[][..]).into(),
                        },
                        padding,
                    )?
                    .encode(),
            );
        }
        if records
            .iter()
            .map(Vec::len)
            .sum::<usize>()
            > MAX_FLIGHT_SIZE
        {
            return Err(invalid());
        }
        Ok(())
    }
}

struct Template {
    suite: CipherSuite,
    group: NamedGroup,
    sid: [u8; 32],
    share: Range<usize>,
}
impl Template {
    fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_RAW_SH {
            return Err(invalid());
        }
        let mut cursor = Cursor::new(raw);
        if cursor.take(4)?
            != [
                2,
                0,
                ((raw.len().saturating_sub(4) >> 8) & 255) as u8,
                (raw.len().saturating_sub(4) & 255) as u8,
            ]
            || cursor.u16()? != 0x0303
        {
            return Err(invalid());
        }
        cursor.take(32)?;
        if cursor.u8()? != 32 {
            return Err(invalid());
        }
        let mut sid = [0; 32];
        sid.copy_from_slice(cursor.take(32)?);
        let suite = CipherSuite::from(cursor.u16()?);
        if !matches!(
            suite,
            CipherSuite::TLS13_AES_128_GCM_SHA256
                | CipherSuite::TLS13_AES_256_GCM_SHA384
                | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        ) || cursor.u8()? != 0
        {
            return Err(invalid());
        }
        let ext_len = usize::from(cursor.u16()?);
        if raw.len().checked_sub(cursor.pos) != Some(ext_len) {
            return Err(invalid());
        }
        let mut version = false;
        let mut kx = None;
        while !cursor.empty() {
            let typ = cursor.u16()?;
            let len = usize::from(cursor.u16()?);
            let start = cursor.pos;
            let value = cursor.take(len)?;
            match typ {
                43 if !version && value == [3, 4] => version = true,
                51 if kx.is_none() => {
                    let mut share = Cursor::new(value);
                    let group = NamedGroup::from(share.u16()?);
                    let len = usize::from(share.u16()?);
                    if len
                        != match group {
                            NamedGroup::X25519 => 32,
                            NamedGroup::X25519MLKEM768 => 1120,
                            _ => return Err(invalid()),
                        }
                    {
                        return Err(invalid());
                    }
                    share.take(len)?;
                    if !share.empty() {
                        return Err(invalid());
                    }
                    kx = Some((group, start + 4..start + 4 + len));
                }
                _ => return Err(invalid()),
            }
        }
        if !version {
            return Err(invalid());
        }
        let (group, share) = kx.ok_or_else(invalid)?;
        // Also require the mature rustls parser to accept exactly this SH.
        let mut reader = Reader::init(raw);
        let parsed = HandshakeMessagePayload::read_version(&mut reader, ProtocolVersion::TLSv1_3)?;
        reader.expect_empty("REALITY ServerHello")?;
        if !matches!(parsed.0, HandshakePayload::ServerHello(_)) {
            return Err(invalid());
        }
        Ok(Self {
            suite,
            group,
            sid,
            share,
        })
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(invalid)?;
        let result = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(invalid)?;
        self.pos = end;
        Ok(result)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn empty(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

pub(crate) fn hello_message(raw: &[u8]) -> Result<Message<'_>, Error> {
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::new(ContentType::Handshake, ProtocolVersion::TLSv1_3, raw)?,
    })
}
