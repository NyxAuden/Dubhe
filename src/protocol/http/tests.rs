use super::*;
use crate::protocol::test_io::Wire;

fn users() -> Vec<User> {
    vec![User {
        name: "u".into(),
        password: "p".into(),
    }]
}
fn request(target: &str, extra: &str) -> Vec<u8> {
    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic dTpw\r\n{extra}\r\n").into_bytes()
}

#[tokio::test]
async fn naive_padded_preserves_combined_or_fragmented_early_bytes_and_identity() {
    let payload = b"\0\x03\x02abc\0\0";
    for fragmented in [false, true] {
        let mut bytes = request("127.0.0.1:443", "Padding: yes\r\n");
        bytes.extend_from_slice(payload);
        let mut wire = Wire::new(bytes);
        if fragmented {
            wire = wire.fragmented();
        }
        let accepted = handshake_naive_padded(&mut wire, &users()).await.unwrap();
        assert_eq!(
            accepted.request.target,
            "127.0.0.1:443"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into()
        );
        assert_eq!(accepted.request.user.as_deref(), Some("u"));
        assert!(accepted.rewritten.is_none());
        assert_eq!(
            [accepted.early, wire.remaining().to_vec()].concat(),
            payload
        );
        assert!(wire.output.is_empty(), "握手解析本身不能提前发送200");
    }
}

#[tokio::test]
async fn only_padded_policy_accepts_exact_v2_magic_at_zero_port() {
    for target in [
        "sp.v2.udp-over-tcp.arpa:0",
        "sp.udp-over-tcp.arpa:0",
        "SP.V2.UDP-OVER-TCP.ARPA:0",
        "example.test:0",
        "127.0.0.1:0",
        "[::1]:0",
    ] {
        let input = request(target, "Padding: yes\r\n");
        let mut wire = Wire::new(input.clone());
        assert!(
            handshake(&mut wire, &users()).await.is_err(),
            "普通HTTP/默认裸H1不可放宽: {target}"
        );
        let mut wire = Wire::new(input);
        let result = handshake_naive_padded(&mut wire, &users()).await;
        assert_eq!(
            result.is_ok(),
            target == "sp.v2.udp-over-tcp.arpa:0",
            "{target}"
        );
        if let Ok(accepted) = result {
            assert_eq!(accepted.request.target.port, 0);
            assert_eq!(
                accepted.request.target.host,
                Host::Domain(crate::udp::UOT_V2_MAGIC.into())
            );
        }
    }
}

#[tokio::test]
async fn padded_policy_requires_connect_single_nonempty_padding_and_valid_basic() {
    for (extra, status) in [
        ("", 400),
        ("Padding: \r\n", 400),
        ("Padding: yes\r\npAdDiNg: again\r\n", 400),
        ("Padding: yes\r\nProxy-Authorization: Basic dTpw\r\n", 407),
    ] {
        let mut wire = Wire::new(request("127.0.0.1:443", extra));
        assert!(handshake_naive_padded(&mut wire, &users()).await.is_err());
        assert!(
            wire.output
                .starts_with(format!("HTTP/1.1 {status}").as_bytes())
        );
    }
    let wrong = String::from_utf8(request("127.0.0.1:443", "Padding: yes\r\n"))
        .unwrap()
        .replace("Basic dTpw", "Basic dTpx");
    let mut wire = Wire::new(wrong.into_bytes());
    assert!(handshake_naive_padded(&mut wire, &users()).await.is_err());
    assert!(wire.output.starts_with(b"HTTP/1.1 407"));
    let get = b"GET http://127.0.0.1:443/path HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\nPadding: yes\r\n\r\n";
    let mut plain = Wire::new(get.to_vec());
    assert!(
        handshake(&mut plain, &users())
            .await
            .unwrap()
            .rewritten
            .is_some()
    );
    let mut padded = Wire::new(get.to_vec());
    assert!(handshake_naive_padded(&mut padded, &users()).await.is_err());
    assert!(padded.output.starts_with(b"HTTP/1.1 400"));
    let mut plain = Wire::new(request("127.0.0.1:443", ""));
    assert!(
        handshake(&mut plain, &users()).await.is_ok(),
        "裸H1不要求Padding"
    );
}

#[tokio::test]
async fn request_head_exact_byte_and_header_limits_do_not_consume_payload_or_accept_overflow() {
    let mut head = request("127.0.0.1:443", "Padding: yes\r\nX: \r\n");
    let position = head.len() - 4;
    head.splice(position..position, vec![b'x'; MAX_HEAD - head.len()]);
    assert_eq!(head.len(), MAX_HEAD);
    for padded in [false, true] {
        let mut with_payload = head.clone();
        with_payload.extend_from_slice(b"early");
        let mut wire = Wire::new(with_payload);
        let accepted = handshake_impl(&mut wire, &users(), padded).await.unwrap();
        assert_eq!(
            [accepted.early, wire.remaining().to_vec()].concat(),
            b"early"
        );
        let mut overflow = head.clone();
        overflow.insert(overflow.len() - 4, b'x');
        let mut wire = Wire::new(overflow);
        assert!(handshake_impl(&mut wire, &users(), padded).await.is_err());
    }
    for count in [64, 65] {
        // Host、认证、Padding共3项。
        let mut extra = "Padding: yes\r\n".to_owned();
        extra.push_str(&"X: y\r\n".repeat(count - 3));
        let mut wire = Wire::new(request("127.0.0.1:443", &extra));
        assert_eq!(
            handshake_naive_padded(&mut wire, &users()).await.is_ok(),
            count == 64
        );
    }
}
