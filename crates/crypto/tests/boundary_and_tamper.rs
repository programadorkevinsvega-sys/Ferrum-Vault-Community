use ferrum_crypto::{Aes256GcmProvider, CryptoError};

const KEY: [u8; 32] = [0x42; 32];
const AAD: &[u8] = b"ferrum/phase-1.1/boundary-test";

#[test]
fn round_trips_empty_block_edges_and_large_payloads() {
    let provider = Aes256GcmProvider::new(&KEY).expect("valid AES-256 key");
    let plaintext_lengths = [
        0, 1, 15, 16, 17, 31, 32, 63, 64, 255, 256, 1023, 1024, 4095, 4096, 16_384, 65_535, 65_536,
        1_048_576,
    ];
    let aad_lengths = [0, 1, 15, 16, 32, 255];

    for plaintext_len in plaintext_lengths {
        let plaintext: Vec<u8> = (0..plaintext_len)
            .map(|index| (index % 251) as u8)
            .collect();

        for aad_len in aad_lengths {
            let aad = vec![0xA5; aad_len];
            let sealed = provider.seal(&aad, &plaintext).expect("seal succeeds");

            assert_eq!(sealed.nonce.len(), 12);
            assert_eq!(sealed.ciphertext_and_tag.len(), plaintext_len + 16);
            assert_eq!(
                provider.open(&aad, &sealed).expect("open succeeds"),
                plaintext,
                "round trip failed for plaintext={plaintext_len}, aad={aad_len}"
            );
        }
    }
}

#[test]
fn every_nonce_ciphertext_and_tag_byte_is_authenticated() {
    let provider = Aes256GcmProvider::new(&KEY).expect("valid AES-256 key");
    let payload = provider
        .seal(AAD, b"authentication mutation coverage")
        .expect("seal succeeds");

    for index in 0..payload.nonce.len() {
        let mut altered = payload.clone();
        altered.nonce[index] ^= 0x01;
        assert_eq!(
            provider.open(AAD, &altered),
            Err(CryptoError::AuthenticationFailed),
            "nonce byte {index} was not authenticated"
        );
    }

    for index in 0..payload.ciphertext_and_tag.len() {
        let mut altered = payload.clone();
        altered.ciphertext_and_tag[index] ^= 0x01;
        assert_eq!(
            provider.open(AAD, &altered),
            Err(CryptoError::AuthenticationFailed),
            "ciphertext/tag byte {index} was not authenticated"
        );
    }

    for index in 0..AAD.len() {
        let mut altered_aad = AAD.to_vec();
        altered_aad[index] ^= 0x01;
        assert_eq!(
            provider.open(&altered_aad, &payload),
            Err(CryptoError::AuthenticationFailed),
            "AAD byte {index} was not authenticated"
        );
    }
}

#[test]
fn truncated_tags_and_extended_envelopes_fail_closed() {
    let provider = Aes256GcmProvider::new(&KEY).expect("valid AES-256 key");
    let payload = provider
        .seal(AAD, b"truncation boundary test")
        .expect("seal succeeds");

    for removed_bytes in 1..=16 {
        let mut truncated = payload.clone();
        let retained_len = truncated.ciphertext_and_tag.len() - removed_bytes;
        truncated.ciphertext_and_tag.truncate(retained_len);
        assert_eq!(
            provider.open(AAD, &truncated),
            Err(CryptoError::AuthenticationFailed),
            "truncating {removed_bytes} trailing bytes must fail"
        );
    }

    let mut extended = payload;
    extended.ciphertext_and_tag.push(0);
    assert_eq!(
        provider.open(AAD, &extended),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn wrong_key_and_wrong_aad_never_release_plaintext() {
    let provider = Aes256GcmProvider::new(&KEY).expect("valid AES-256 key");
    let payload = provider.seal(AAD, b"secret").expect("seal succeeds");
    let wrong_key = [0x24; 32];
    let other_provider = Aes256GcmProvider::new(&wrong_key).expect("valid alternate AES-256 key");

    assert_eq!(
        provider.open(b"wrong context", &payload),
        Err(CryptoError::AuthenticationFailed)
    );
    assert_eq!(
        other_provider.open(AAD, &payload),
        Err(CryptoError::AuthenticationFailed)
    );
}
