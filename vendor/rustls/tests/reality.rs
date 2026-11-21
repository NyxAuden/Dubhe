//! 自持内存 TLS peer：不调用项目 REALITY parser/auth/certificate。
use ring::signature::KeyPair as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs, ring as ring_provider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::reality::{Config, RecordPlan, ResolvesCertificate};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, RootCertStore, ServerConfig,
    ServerConnection, SignatureScheme,
};
use std::{
    io::{Cursor, Read, Write},
    sync::{Arc, Mutex},
};

struct Remote(Arc<ring::signature::Ed25519KeyPair>);
impl rcgen::RemoteKeyPair for Remote {
    fn public_key(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.0.sign(msg).as_ref().to_vec())
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}
fn certificate(extension_len: usize) -> Arc<CertifiedKey> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let remote = Remote(Arc::new(
        ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
    ));
    let pair = rcgen::KeyPair::from_remote(Box::new(remote)).unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.serial_number = Some(rcgen::SerialNumber::from(1u64));
    if extension_len != 0 {
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[0, 0],
                vec![1; extension_len],
            ));
    }
    let cert = params.self_signed(&pair).unwrap();
    Arc::new(
        CertifiedKey::from_der(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec())),
            &aws_lc_rs::default_provider(),
        )
        .unwrap(),
    )
}
fn provider(group: rustls::NamedGroup, suite: rustls::CipherSuite) -> Arc<CryptoProvider> {
    let mut provider = aws_lc_rs::default_provider();
    provider
        .kx_groups
        .retain(|item| item.name() == group);
    provider
        .cipher_suites
        .retain(|item| item.suite() == suite);
    Arc::new(provider)
}
fn server_config(key: Arc<CertifiedKey>, provider: Arc<CryptoProvider>) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(key)));
    config.send_tls13_tickets = 0;
    config.max_tls13_tickets = 0;
    config.cert_compressors.clear();
    config
}
#[derive(Debug)]
struct Verify(Arc<CryptoProvider>);
impl ServerCertVerifier for Verify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0
            .signature_verification_algorithms
            .supported_schemes()
    }
}
fn client(provider: Arc<CryptoProvider>) -> ClientConnection {
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verify(provider)))
        .with_no_client_auth();
    ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap()).unwrap()
}
fn drain_client(client: &mut ClientConnection) -> Vec<u8> {
    let mut out = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut out).unwrap();
    }
    out
}
fn drain_server(server: &mut ServerConnection) -> Vec<u8> {
    let mut out = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut out).unwrap();
    }
    out
}
fn records(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos != bytes.len() {
        let len = usize::from(u16::from_be_bytes([bytes[pos + 3], bytes[pos + 4]])) + 5;
        out.push(&bytes[pos..pos + len]);
        pos += len;
    }
    out
}
#[derive(Debug)]
struct Resolver {
    key: Arc<CertifiedKey>,
    observed: Arc<Mutex<Vec<Vec<u8>>>>,
    fail: bool,
}
impl ResolvesCertificate for Resolver {
    fn resolve(&self, raw: &[u8]) -> Result<Arc<CertifiedKey>, Error> {
        self.observed
            .lock()
            .unwrap()
            .push(raw.to_vec());
        if self.fail {
            return Err(Error::General("intentional callback failure".into()));
        }
        Ok(self.key.clone())
    }
}
fn setup(
    group: rustls::NamedGroup,
    suite: rustls::CipherSuite,
    encrypted: Vec<usize>,
    empty_app: Option<usize>,
    cert_size: usize,
    ccs: usize,
) -> (
    ClientConnection,
    ServerConnection,
    Vec<u8>,
    Vec<u8>,
    Arc<Mutex<Vec<Vec<u8>>>>,
    Arc<Secrets>,
) {
    let provider = provider(group, suite);
    let key = certificate(cert_size);
    let mut client = client(provider.clone());
    let ch = drain_client(&mut client);
    let mut target =
        ServerConnection::new(Arc::new(server_config(key.clone(), provider.clone()))).unwrap();
    target
        .read_tls(&mut Cursor::new(&ch))
        .unwrap();
    target.process_new_packets().unwrap();
    let flight = drain_server(&mut target);
    let raw = records(&flight)[0][5..].to_vec();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let plan = RecordPlan::new(raw.len() + 5, ccs, encrypted, empty_app).unwrap();
    let hook = Config::new(
        raw.clone(),
        plan,
        Arc::new(Resolver {
            key: key.clone(),
            observed: seen.clone(),
            fail: false,
        }),
    )
    .unwrap();
    let mut config = server_config(key, provider);
    config.reality = Some(Arc::new(hook));
    let secrets = Arc::new(Secrets::default());
    config.key_log = secrets.clone();
    (
        client,
        ServerConnection::new(Arc::new(config)).unwrap(),
        ch,
        raw,
        seen,
        secrets,
    )
}
#[derive(Debug, Default)]
struct Secrets(Mutex<Vec<(String, Vec<u8>)>>);
impl rustls::KeyLog for Secrets {
    fn log(&self, label: &str, _: &[u8], secret: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .push((label.into(), secret.to_vec()));
    }
}
fn expand_label(secret: &[u8], label: &[u8], len: usize, alg: ring::hkdf::Algorithm) -> Vec<u8> {
    struct Len(usize);
    impl ring::hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    let mut info = (len as u16).to_be_bytes().to_vec();
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    let mut out = vec![0; len];
    ring::hkdf::Prk::new_less_safe(alg, secret)
        .expand(&[&info], Len(len))
        .unwrap()
        .fill(&mut out)
        .unwrap();
    out
}
fn independent_decrypt(
    record: &[u8],
    secret: &[u8],
    suite: rustls::CipherSuite,
    seq: u64,
) -> Vec<u8> {
    let (aead, hkdf, key_len) = match suite {
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => {
            (&ring::aead::AES_128_GCM, ring::hkdf::HKDF_SHA256, 16)
        }
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => {
            (&ring::aead::AES_256_GCM, ring::hkdf::HKDF_SHA384, 32)
        }
        _ => (&ring::aead::CHACHA20_POLY1305, ring::hkdf::HKDF_SHA256, 32),
    };
    let key = expand_label(secret, b"key", key_len, hkdf);
    let mut iv = expand_label(secret, b"iv", 12, hkdf);
    for (a, b) in iv[4..]
        .iter_mut()
        .zip(seq.to_be_bytes())
    {
        *a ^= b;
    }
    let nonce = ring::aead::Nonce::try_assume_unique_for_key(&iv).unwrap();
    let mut payload = record[5..].to_vec();
    ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(aead, &key).unwrap())
        .open_in_place(nonce, ring::aead::Aad::from(&record[..5]), &mut payload)
        .unwrap()
        .to_vec()
}
fn independent_flight(
    ch: &[u8],
    flight: &[u8],
    suite: rustls::CipherSuite,
    secrets: &Secrets,
    separated: bool,
    empty_app: bool,
) {
    let log = secrets.0.lock().unwrap();
    let handshake_secret = &log
        .iter()
        .find(|(label, _)| label == "SERVER_HANDSHAKE_TRAFFIC_SECRET")
        .unwrap()
        .1;
    let app_secret = &log
        .iter()
        .find(|(label, _)| label == "SERVER_TRAFFIC_SECRET_0")
        .unwrap()
        .1;
    let all_records = records(flight);
    let mut transcript = records(ch)[0][5..].to_vec();
    transcript.extend_from_slice(&all_records[0][5..]);
    let encrypted = all_records
        .iter()
        .filter(|record| record[0] == 23)
        .copied()
        .collect::<Vec<_>>();
    let count = if separated { 4 } else { 1 };
    let mut body = Vec::new();
    for (seq, record) in encrypted[..count].iter().enumerate() {
        let plain = independent_decrypt(record, handshake_secret, suite, seq as u64);
        let type_pos = plain
            .iter()
            .rposition(|byte| *byte != 0)
            .unwrap();
        assert_eq!(plain[type_pos], 22);
        assert!(
            plain[type_pos + 1..]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(type_pos + 1 < plain.len());
        body.extend_from_slice(&plain[..type_pos]);
    }
    let (digest, hkdf, hmac) = if suite == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 {
        (
            &ring::digest::SHA384,
            ring::hkdf::HKDF_SHA384,
            ring::hmac::HMAC_SHA384,
        )
    } else {
        (
            &ring::digest::SHA256,
            ring::hkdf::HKDF_SHA256,
            ring::hmac::HMAC_SHA256,
        )
    };
    let mut pos = 0;
    let mut kinds = Vec::new();
    while pos < body.len() {
        let len = ((body[pos + 1] as usize) << 16)
            | ((body[pos + 2] as usize) << 8)
            | body[pos + 3] as usize;
        let end = pos + 4 + len;
        kinds.push(body[pos]);
        if body[pos] == 20 {
            let hash = ring::digest::digest(digest, &transcript);
            let finished_key =
                expand_label(handshake_secret, b"finished", digest.output_len(), hkdf);
            ring::hmac::verify(
                &ring::hmac::Key::new(hmac, &finished_key),
                hash.as_ref(),
                &body[pos + 4..end],
            )
            .unwrap();
        }
        transcript.extend_from_slice(&body[pos..end]);
        pos = end;
    }
    assert_eq!(kinds, vec![8, 11, 15, 20]);
    if empty_app {
        let plain = independent_decrypt(encrypted[count], app_secret, suite, 0);
        assert_eq!(plain[0], 23);
        assert!(plain[1..].iter().all(|byte| *byte == 0));
    }
}
fn exercise(
    group: rustls::NamedGroup,
    suite: rustls::CipherSuite,
    encrypted: Vec<usize>,
    empty_app: Option<usize>,
    cert_size: usize,
    ccs: usize,
) {
    let (mut client, mut server, ch, target_sh, seen, secrets) =
        setup(group, suite, encrypted.clone(), empty_app, cert_size, ccs);
    server
        .read_tls(&mut Cursor::new(&ch))
        .unwrap();
    server.process_new_packets().unwrap();
    assert!(server.is_handshaking());
    let flight = drain_server(&mut server);
    let actual = records(&flight);
    let mut expected = vec![target_sh.len() + 5];
    if ccs != 0 {
        expected.push(ccs);
    }
    expected.extend(encrypted);
    expected.extend(empty_app);
    assert_eq!(
        actual
            .iter()
            .map(|r| r.len())
            .collect::<Vec<_>>(),
        expected
    );
    let final_sh = seen.lock().unwrap()[0].clone();
    assert_eq!(&actual[0][5..], &final_sh);
    assert_ne!(final_sh, target_sh); // independent, fresh local KX share
    assert_eq!(&final_sh[..38], &target_sh[..38]); // random and encoding retained
    independent_flight(
        &ch,
        &flight,
        suite,
        &secrets,
        expected.len() - usize::from(ccs != 0) - 1 - usize::from(empty_app.is_some()) == 4,
        empty_app.is_some(),
    );
    let mut input = Cursor::new(flight);
    while input.position() < input.get_ref().len() as u64 {
        client.read_tls(&mut input).unwrap();
        client.process_new_packets().unwrap();
    }
    let finished = drain_client(&mut client);
    assert!(!finished.is_empty());
    server
        .read_tls(&mut Cursor::new(finished))
        .unwrap();
    server.process_new_packets().unwrap();
    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
    // Optional empty application record consumed sequence 0, not application
    // plaintext: the next genuine record must still decrypt correctly.
    server
        .writer()
        .write_all(b"genuine application")
        .unwrap();
    client
        .read_tls(&mut Cursor::new(drain_server(&mut server)))
        .unwrap();
    client.process_new_packets().unwrap();
    let mut body = Vec::new();
    client
        .reader()
        .read_to_end(&mut body)
        .unwrap_err();
    assert_eq!(body, b"genuine application");
    server.refresh_traffic_keys().unwrap();
    server
        .writer()
        .write_all(b"after key update")
        .unwrap();
    let mut input = Cursor::new(drain_server(&mut server));
    while input.position() < input.get_ref().len() as u64 {
        client.read_tls(&mut input).unwrap();
        client.process_new_packets().unwrap();
    }
    let mut body = Vec::new();
    client
        .reader()
        .read_to_end(&mut body)
        .unwrap_err();
    assert_eq!(body, b"after key update");
}
#[test]
fn x25519_aggregated_and_empty_app_all_suites() {
    for suite in [
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        exercise(
            rustls::NamedGroup::X25519,
            suite,
            vec![4096],
            Some(128),
            0,
            6,
        );
    }
}
#[test]
fn hybrid_aggregated_large_certificate() {
    exercise(
        rustls::NamedGroup::X25519MLKEM768,
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        vec![8192],
        Some(64),
        3309,
        6,
    );
}
#[test]
fn separated_layout_and_absent_ccs() {
    exercise(
        rustls::NamedGroup::X25519,
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        vec![128, 4096, 256, 128],
        None,
        3309,
        0,
    );
}
#[test]
fn insufficient_target_slot_uses_natural_record_lengths() {
    // 目标 flight 的记录槽位小于本地证书时，仍应完成握手并使用自然长度；
    // 记录条数与布局形态保持不变。这与 Xray REALITY 不要求逐 record 等长一致。
    let (_, mut server, ch, _, _, _) = setup(
        rustls::NamedGroup::X25519,
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        vec![128, 128, 128, 128],
        None,
        3309,
        6,
    );
    server
        .read_tls(&mut Cursor::new(ch))
        .unwrap();
    server.process_new_packets().unwrap();
    assert!(server.wants_write());
    assert!(!drain_server(&mut server).is_empty());
}
#[test]
fn record_plan_boundaries() {
    assert!(RecordPlan::new(100, 6, vec![16_406], None).is_ok());
    assert!(RecordPlan::new(100, 6, vec![16_407], None).is_err());
    assert!(RecordPlan::new(100, 6, vec![512], None).is_err());
    assert!(RecordPlan::new(100, 6, vec![513, 100, 100, 100], None).is_err());
    assert!(RecordPlan::new(100, 6, vec![], None).is_err());
    assert!(RecordPlan::new(100, 7, vec![1024], None).is_err());
    assert!(RecordPlan::new(usize::MAX, 6, vec![1024], None).is_err());
    assert!(RecordPlan::new(100, 6, vec![1024], Some(21)).is_err());
}
fn raw_template() -> (Vec<u8>, Vec<u8>, Arc<CertifiedKey>) {
    let key = certificate(0);
    let p = provider(
        rustls::NamedGroup::X25519,
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
    );
    let mut client = client(p.clone());
    let ch = drain_client(&mut client);
    let mut target = ServerConnection::new(Arc::new(server_config(key.clone(), p))).unwrap();
    target
        .read_tls(&mut Cursor::new(&ch))
        .unwrap();
    target.process_new_packets().unwrap();
    (
        records(&drain_server(&mut target))[0][5..].to_vec(),
        ch,
        key,
    )
}
fn hook(raw: Vec<u8>, key: Arc<CertifiedKey>, fail: bool) -> Config {
    let plan = RecordPlan::new(raw.len() + 5, 6, vec![4096], None).unwrap();
    Config::new(
        raw,
        plan,
        Arc::new(Resolver {
            key,
            observed: Arc::new(Mutex::new(vec![])),
            fail,
        }),
    )
    .unwrap()
}
fn rejects_flight(mut config: ServerConfig, hook: Config, ch: &[u8]) {
    config.reality = Some(Arc::new(hook));
    let mut server = ServerConnection::new(Arc::new(config)).unwrap();
    server
        .read_tls(&mut Cursor::new(ch))
        .unwrap();
    assert!(server.process_new_packets().is_err());
    assert!(drain_server(&mut server).is_empty());
    // Errors are latched: no second attempt, no partial output on retry.
    assert!(server.process_new_packets().is_err());
    assert!(drain_server(&mut server).is_empty());
}
#[test]
fn raw_server_hello_strict_validation_and_truncations() {
    let (raw, _, key) = raw_template();
    let valid = |raw: Vec<u8>| {
        let plan = RecordPlan::new(raw.len() + 5, 6, vec![4096], None).unwrap();
        Config::new(
            raw,
            plan,
            Arc::new(Resolver {
                key: key.clone(),
                observed: Arc::new(Mutex::new(vec![])),
                fail: false,
            }),
        )
        .is_ok()
    };
    assert!(valid(raw.clone()));
    for len in 0..raw.len() {
        assert!(!valid(raw[..len].to_vec()), "truncated at {len}");
    }
    for (offset, value) in [
        (0, 1),
        (1, 1),
        (2, 1),
        (4, 2),
        (38, 31),
        (71, 0x12),
        (72, 4),
        (73, 1),
        (77, 44),
    ] {
        let mut bad = raw.clone();
        bad[offset] = value;
        assert!(!valid(bad), "invalid at {offset}");
    }
    let mut hrr = raw.clone();
    hrr[6..38].copy_from_slice(&[
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ]);
    assert!(!valid(hrr));
    let mut duplicate = raw.clone();
    duplicate.extend_from_slice(&[0, 43, 0, 2, 3, 4]);
    let len = duplicate.len() - 4;
    duplicate[1..4].copy_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    let ext = duplicate.len() - 76;
    duplicate[74..76].copy_from_slice(&(ext as u16).to_be_bytes());
    assert!(!valid(duplicate));
    let plan = RecordPlan::new(raw.len() + 6, 6, vec![4096], None).unwrap();
    assert!(
        Config::new(
            raw,
            plan,
            Arc::new(Resolver {
                key,
                observed: Arc::new(Mutex::new(vec![])),
                fail: false
            })
        )
        .is_err()
    );
}
#[test]
fn template_offers_session_and_provider_rechecked() {
    let (raw, ch, key) = raw_template();
    let p = || {
        provider(
            rustls::NamedGroup::X25519,
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        )
    };
    let mut bad = raw.clone();
    bad[39] ^= 1;
    rejects_flight(
        server_config(key.clone(), p()),
        hook(bad, key.clone(), false),
        &ch,
    );
    let mut bad = raw.clone();
    bad[72] = 2; // allowed suite, but not CH offered
    rejects_flight(
        server_config(key.clone(), p()),
        hook(bad, key.clone(), false),
        &ch,
    );
    let hybrid_p = provider(
        rustls::NamedGroup::X25519MLKEM768,
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
    );
    rejects_flight(
        server_config(key.clone(), hybrid_p),
        hook(raw.clone(), key.clone(), false),
        &ch,
    );
    // ring has the same advertised suite/group but cannot perform opt-in padding.
    rejects_flight(
        server_config(key.clone(), Arc::new(ring_provider::default_provider())),
        hook(raw, key, false),
        &ch,
    );
}
#[test]
fn callback_failure_key_swap_and_spki_mismatch_have_no_output() {
    let (raw, ch, key) = raw_template();
    let p = || {
        provider(
            rustls::NamedGroup::X25519,
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        )
    };
    rejects_flight(
        server_config(key.clone(), p()),
        hook(raw.clone(), key.clone(), true),
        &ch,
    );
    let other = certificate(0);
    rejects_flight(
        server_config(key.clone(), p()),
        hook(raw.clone(), other.clone(), false),
        &ch,
    );
    let mismatched = Arc::new(CertifiedKey::new(other.cert.clone(), key.key.clone()));
    rejects_flight(
        server_config(key.clone(), p()),
        hook(raw.clone(), mismatched, false),
        &ch,
    );
    let oversized = Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(vec![0; 65537])],
        key.key.clone(),
    ));
    rejects_flight(
        server_config(key.clone(), p()),
        hook(raw, oversized, false),
        &ch,
    );
}
#[test]
fn invalid_client_finished_never_delivers_application() {
    let (mut client, mut server, ch, _, _, _) = setup(
        rustls::NamedGroup::X25519,
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        vec![4096],
        None,
        0,
        6,
    );
    server
        .read_tls(&mut Cursor::new(ch))
        .unwrap();
    server.process_new_packets().unwrap();
    let mut input = Cursor::new(drain_server(&mut server));
    while input.position() < input.get_ref().len() as u64 {
        client.read_tls(&mut input).unwrap();
        client.process_new_packets().unwrap();
    }
    let mut finished = drain_client(&mut client);
    let end = finished.len() - 1;
    finished[end] ^= 1;
    server
        .read_tls(&mut Cursor::new(finished))
        .unwrap();
    assert!(server.process_new_packets().is_err());
    assert!(server.is_handshaking());
    let mut byte = [0];
    assert!(server.reader().read(&mut byte).is_err());
}
#[test]
fn aead_limit_failure_is_fallible_and_atomic() {
    let (raw, ch, key) = raw_template();
    let mut p = (*provider(
        rustls::NamedGroup::X25519,
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
    ))
    .clone();
    let original = p.cipher_suites[0].tls13().unwrap();
    let limited = Box::leak(Box::new(rustls::Tls13CipherSuite {
        common: rustls::CipherSuiteCommon {
            suite: original.common.suite,
            hash_provider: original.common.hash_provider,
            confidentiality_limit: 1,
        },
        hkdf_provider: original.hkdf_provider,
        aead_alg: original.aead_alg,
        quic: None,
    }));
    p.cipher_suites = vec![rustls::SupportedCipherSuite::Tls13(limited)];
    let plan = RecordPlan::new(raw.len() + 5, 6, vec![128, 1024, 256, 128], None).unwrap();
    let hook = Config::new(
        raw,
        plan,
        Arc::new(Resolver {
            key: key.clone(),
            observed: Arc::new(Mutex::new(vec![])),
            fail: false,
        }),
    )
    .unwrap();
    rejects_flight(server_config(key, Arc::new(p)), hook, &ch);
}
#[test]
fn tls_inner_plaintext_exact_limit() {
    exercise(
        rustls::NamedGroup::X25519,
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        vec![16406],
        Some(16406),
        0,
        6,
    );
}
#[test]
fn ordinary_ring_no_hook_real_certificate_and_finished() {
    ordinary_ring(&rustls::version::TLS13);
}
#[test]
fn ordinary_ring_tls12_no_hook() {
    ordinary_ring(&rustls::version::TLS12);
}
fn ordinary_ring(version: &'static rustls::SupportedProtocolVersion) {
    let key = certificate(0);
    let mut config = server_config(key.clone(), Arc::new(ring_provider::default_provider()));
    assert!(config.reality.is_none());
    if version.version == rustls::ProtocolVersion::TLSv1_2 {
        config = ServerConfig::builder_with_provider(Arc::new(ring_provider::default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(key.clone())));
    }
    config.send_tls13_tickets = 2;
    let mut roots = RootCertStore::empty();
    roots.add(key.cert[0].clone()).unwrap();
    let client_config =
        ClientConfig::builder_with_provider(Arc::new(ring_provider::default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let mut client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(Arc::new(config)).unwrap();
    for _ in 0..5 {
        let bytes = drain_client(&mut client);
        if !bytes.is_empty() {
            server
                .read_tls(&mut Cursor::new(bytes))
                .unwrap();
            server.process_new_packets().unwrap();
        }
        let bytes = drain_server(&mut server);
        if !bytes.is_empty() {
            client
                .read_tls(&mut Cursor::new(bytes))
                .unwrap();
            client.process_new_packets().unwrap();
        }
    }
    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
}
