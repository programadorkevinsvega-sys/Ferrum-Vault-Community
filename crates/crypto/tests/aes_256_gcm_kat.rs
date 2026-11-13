mod support;

use aws_lc_rs::aead::{Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_256_GCM};

use support::{decode_hex, FixedNonce};

fn assert_aes_256_gcm_kat(
    key_hex: &str,
    nonce_hex: &str,
    plaintext_hex: &str,
    ciphertext_hex: &str,
    tag_hex: &str,
) {
    let key = decode_hex(key_hex);
    let nonce_bytes = decode_hex(nonce_hex);
    let nonce: [u8; 12] = nonce_bytes.try_into().expect("96-bit test nonce");
    let plaintext = decode_hex(plaintext_hex);
    let expected_ciphertext = decode_hex(ciphertext_hex);
    let expected_tag = decode_hex(tag_hex);

    let mut ciphertext = plaintext.clone();
    let mut sealing_key = SealingKey::new(
        UnboundKey::new(&AES_256_GCM, &key).expect("valid AES-256 key"),
        FixedNonce(nonce),
    );
    let actual_tag = sealing_key
        .seal_in_place_separate_tag(Aad::empty(), &mut ciphertext)
        .expect("AES-256-GCM seal succeeds");

    assert_eq!(ciphertext, expected_ciphertext);
    assert_eq!(actual_tag.as_ref(), expected_tag);

    let mut ciphertext_and_tag = expected_ciphertext;
    ciphertext_and_tag.extend_from_slice(&expected_tag);
    let mut opening_key = OpeningKey::new(
        UnboundKey::new(&AES_256_GCM, &key).expect("valid AES-256 key"),
        FixedNonce(nonce),
    );
    let recovered = opening_key
        .open_in_place(Aad::empty(), &mut ciphertext_and_tag)
        .expect("AES-256-GCM KAT authenticates");

    assert_eq!(recovered, plaintext);
}

#[test]
fn nist_aes_256_gcm_empty_plaintext_known_answer() {
    assert_aes_256_gcm_kat(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "",
        "",
        "530f8afbc74536b9a963b4f1c4cb738b",
    );
}

#[test]
fn nist_aes_256_gcm_single_block_known_answer() {
    assert_aes_256_gcm_kat(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000",
        "00000000000000000000000000000000",
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919",
    );
}
