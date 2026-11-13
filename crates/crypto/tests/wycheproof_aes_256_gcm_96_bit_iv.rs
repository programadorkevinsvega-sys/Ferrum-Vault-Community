mod support;

use aws_lc_rs::aead::{AES_256_GCM, Aad, BoundKey, OpeningKey, SealingKey, UnboundKey};
use serde_json::Value;

use support::{FixedNonce, decode_hex};

const WYCHEPROOF_VECTORS: &str = include_str!("vectors/aes_gcm_test.json");

#[test]
fn wycheproof_aes_256_gcm_96_bit_iv_profile() {
    let document: Value =
        serde_json::from_str(WYCHEPROOF_VECTORS).expect("Wycheproof JSON is valid");
    let groups = document["testGroups"]
        .as_array()
        .expect("testGroups array is present");

    let mut matching_groups = 0;
    let mut valid_cases = 0;
    let mut invalid_cases = 0;

    for group in groups {
        if group["keySize"].as_u64() != Some(256)
            || group["ivSize"].as_u64() != Some(96)
            || group["tagSize"].as_u64() != Some(128)
        {
            continue;
        }

        matching_groups += 1;
        let cases = group["tests"].as_array().expect("tests array is present");

        for case in cases {
            let case_id = case["tcId"].as_u64().expect("tcId is numeric");
            let key = decode_hex(case["key"].as_str().expect("key is hex"));
            let nonce_bytes = decode_hex(case["iv"].as_str().expect("iv is hex"));
            let nonce: [u8; 12] = nonce_bytes.try_into().expect("96-bit IV");
            let aad = decode_hex(case["aad"].as_str().expect("aad is hex"));
            let message = decode_hex(case["msg"].as_str().expect("msg is hex"));
            let ciphertext = decode_hex(case["ct"].as_str().expect("ct is hex"));
            let tag = decode_hex(case["tag"].as_str().expect("tag is hex"));
            let result = case["result"].as_str().expect("result is present");

            let mut ciphertext_and_tag = ciphertext.clone();
            ciphertext_and_tag.extend_from_slice(&tag);
            let mut opening_key = OpeningKey::new(
                UnboundKey::new(&AES_256_GCM, &key).expect("valid AES-256 vector key"),
                FixedNonce(nonce),
            );

            match result {
                "valid" => {
                    let mut generated_ciphertext = message.clone();
                    let mut sealing_key = SealingKey::new(
                        UnboundKey::new(&AES_256_GCM, &key).expect("valid AES-256 vector key"),
                        FixedNonce(nonce),
                    );
                    let generated_tag = sealing_key
                        .seal_in_place_separate_tag(
                            Aad::from(aad.as_slice()),
                            &mut generated_ciphertext,
                        )
                        .unwrap_or_else(|_| panic!("Wycheproof tcId {case_id}: seal failed"));

                    assert_eq!(
                        generated_ciphertext, ciphertext,
                        "Wycheproof tcId {case_id}: ciphertext mismatch"
                    );
                    assert_eq!(
                        generated_tag.as_ref(),
                        tag,
                        "Wycheproof tcId {case_id}: tag mismatch"
                    );

                    let plaintext = opening_key
                        .open_in_place(Aad::from(aad.as_slice()), &mut ciphertext_and_tag)
                        .unwrap_or_else(|_| {
                            panic!("Wycheproof tcId {case_id}: valid vector rejected")
                        });
                    assert_eq!(
                        plaintext, message,
                        "Wycheproof tcId {case_id}: plaintext mismatch"
                    );
                    valid_cases += 1;
                }
                "invalid" => {
                    assert!(
                        opening_key
                            .open_in_place(Aad::from(aad.as_slice()), &mut ciphertext_and_tag)
                            .is_err(),
                        "Wycheproof tcId {case_id}: invalid vector accepted"
                    );
                    invalid_cases += 1;
                }
                other => panic!("Wycheproof tcId {case_id}: unexpected result class {other}"),
            }
        }
    }

    assert_eq!(matching_groups, 1, "one approved AES-256-GCM profile");
    assert_eq!(valid_cases, 39, "all valid profile vectors were exercised");
    assert_eq!(
        invalid_cases, 27,
        "all invalid profile vectors were rejected"
    );
}
