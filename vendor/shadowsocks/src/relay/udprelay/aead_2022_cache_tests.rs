//! 本内核缓存禁用补丁的差异与状态测试；不替代端到端互通验收。
use super::*;
use crate::config::ServerType;

fn methods() -> [CipherKind; 3] {
    [
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
        CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
        CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
    ]
}

#[test]
fn cached_and_uncached_ciphertext_is_identical() {
    for method in methods() {
        let key = vec![0x47; method.key_len()];
        for sid in [0, 1, 0x123456789abcdef0, u64::MAX] {
            CIPHER_CACHE.with(|cache| cache.borrow_mut().clear());
            let cached = cached_cipher(method, &key, sid);
            let uncached = get_cipher(method, &key, sid);
            let nonce_length = if method == CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 {
                24
            } else {
                12
            };
            let nonce = vec![0x23; nonce_length];
            let mut expected = vec![0x65; 128 + method.tag_len()];
            let mut actual = expected.clone();
            cached.encrypt_packet(&nonce, &mut expected);
            uncached.encrypt_packet(&nonce, &mut actual);
            assert_eq!(actual, expected, "{method}, sid={sid}");
            assert!(uncached.decrypt_packet(&nonce, &mut expected));
            assert!(cached.decrypt_packet(&nonce, &mut actual));
            assert_eq!(&actual[..128], &[0x65; 128]);
            assert_eq!(actual, expected);
            drop(cached);
            drop(uncached);
        }
    }
    CIPHER_CACHE.with(|cache| cache.borrow_mut().clear());
}

#[test]
fn valid_packets_and_invalid_tags_do_not_fill_cache() {
    let context = Context::new(ServerType::Server);
    let address: Address = "127.0.0.1:1234".parse().unwrap();
    for method in methods() {
        CIPHER_CACHE.with(|cache| cache.borrow_mut().clear());
        let key = vec![0x61; method.key_len()];
        for sid in 1..=2048 {
            let mut control = UdpSocketControlData::default();
            control.client_session_id = sid;
            control.server_session_id = sid + 10_000;
            control.packet_id = sid * 2;
            let mut wire = BytesMut::new();
            encrypt_client_payload_aead_2022(
                &context,
                method,
                &key,
                &address,
                &control,
                &[],
                b"cache-test",
                &mut wire,
            );
            let mut corrupt = wire.to_vec();
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(
                decrypt_client_payload_aead_2022(&context, method, &key, &mut corrupt, None)
                    .is_err()
            );
            let (n, target, returned) =
                decrypt_client_payload_aead_2022(&context, method, &key, &mut wire, None).unwrap();
            assert_eq!(target, address);
            assert_eq!(&wire[..n], b"cache-test");
            assert_eq!(returned.client_session_id, sid);
            assert_eq!(returned.packet_id, control.packet_id);
            let mut response = BytesMut::new();
            encrypt_server_payload_aead_2022(
                &context,
                method,
                &key,
                &address,
                &control,
                b"response",
                &mut response,
            );
            let (n, target, returned) =
                decrypt_server_payload_aead_2022(&context, method, &key, &mut response).unwrap();
            assert_eq!(target, address);
            assert_eq!(&response[..n], b"response");
            assert_eq!(returned.client_session_id, sid);
            assert_eq!(returned.server_session_id, control.server_session_id);
            CIPHER_CACHE.with(|cache| assert_eq!(cache.borrow().len(), 0));
        }
    }
}
