#![no_main]

use ferrum_crypto::Aes256GcmProvider;
use libfuzzer_sys::fuzz_target;

const KEY: [u8; 32] = [0x42; 32];

fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 {
        return;
    }

    let split = if data.is_empty() {
        0
    } else {
        usize::from(data[0]) % (data.len() + 1)
    };
    let (aad, plaintext) = data.split_at(split);

    let provider = Aes256GcmProvider::new(&KEY).expect("fixed AES-256 key is valid");
    let sealed = provider.seal(aad, plaintext).expect("seal must not panic");
    assert_eq!(sealed.nonce.len(), 12);
    assert_eq!(sealed.ciphertext_and_tag.len(), plaintext.len() + 16);

    let opened = provider
        .open(aad, &sealed)
        .expect("a provider-generated envelope must authenticate");
    assert_eq!(opened.as_slice(), plaintext);
});
