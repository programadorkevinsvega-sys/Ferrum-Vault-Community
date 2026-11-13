#![no_main]

use ferrum_crypto::{Aes256GcmProvider, CryptoError};
use libfuzzer_sys::fuzz_target;

const KEY: [u8; 32] = [0x42; 32];

fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 {
        return;
    }

    let split = data.len() / 2;
    let (aad, plaintext) = data.split_at(split);
    let provider = Aes256GcmProvider::new(&KEY).expect("fixed AES-256 key is valid");
    let sealed = provider.seal(aad, plaintext).expect("seal must not panic");

    let mut altered_aad = aad.to_vec();
    if altered_aad.is_empty() {
        altered_aad.push(0);
    } else {
        altered_aad[0] ^= 0x01;
    }
    assert_eq!(
        provider.open(&altered_aad, &sealed),
        Err(CryptoError::AuthenticationFailed)
    );

    let mut altered_nonce = sealed.clone();
    altered_nonce.nonce[0] ^= 0x01;
    assert_eq!(
        provider.open(aad, &altered_nonce),
        Err(CryptoError::AuthenticationFailed)
    );

    if !plaintext.is_empty() {
        let mut altered_ciphertext = sealed.clone();
        altered_ciphertext.ciphertext_and_tag[0] ^= 0x01;
        assert_eq!(
            provider.open(aad, &altered_ciphertext),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    let mut altered_tag = sealed;
    let last = altered_tag
        .ciphertext_and_tag
        .last_mut()
        .expect("AES-GCM always appends a 16-byte tag");
    *last ^= 0x01;
    assert_eq!(
        provider.open(aad, &altered_tag),
        Err(CryptoError::AuthenticationFailed)
    );
});
