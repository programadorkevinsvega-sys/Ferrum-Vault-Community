#![no_main]

use ferrum_crypto::{Aes256GcmProvider, SealedPayload};
use libfuzzer_sys::fuzz_target;

const KEY: [u8; 32] = [0x42; 32];

fuzz_target!(|data: &[u8]| {
    if data.len() < 14 || data.len() > 1_048_576 {
        return;
    }

    let requested_aad_len = usize::from(u16::from_le_bytes([data[0], data[1]]));
    let max_aad_len = data.len() - 14;
    let aad_len = if max_aad_len == 0 {
        0
    } else {
        requested_aad_len % (max_aad_len + 1)
    };

    let aad = &data[2..2 + aad_len];
    let envelope = &data[2 + aad_len..];
    let nonce: [u8; 12] = envelope[..12]
        .try_into()
        .expect("the input partition reserves a 96-bit nonce");
    let payload = SealedPayload {
        nonce,
        ciphertext_and_tag: envelope[12..].to_vec(),
    };

    let provider = Aes256GcmProvider::new(&KEY).expect("fixed AES-256 key is valid");
    // Errors are expected for attacker-controlled bytes. Panics, hangs or
    // memory-safety failures are findings; successful output is authenticated.
    let _ = provider.open(aad, &payload);
});
