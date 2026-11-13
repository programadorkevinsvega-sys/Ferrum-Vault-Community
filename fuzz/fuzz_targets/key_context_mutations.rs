#![no_main]
use libfuzzer_sys::fuzz_target;
use ferrum_crypto::{Aes256GcmProvider, CryptoError, kmp::{KeyContext, KeyPurpose}};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 { return; }

    // First byte selects a non-empty scope prefix; the following byte selects
    // a mutation position inside that scope. Remaining bytes are plaintext.
    let split = 1 + (usize::from(data[0]) % (data.len() - 1));
    let mut scope = data[1..split].to_vec();
    if scope.is_empty() { return; }
    let mutation_selector = data[split];
    let plaintext = &data[split + 1..];

    let original_context = match KeyContext::new(KeyPurpose::DataEncryptionKey, &scope) {
        Ok(context) => context,
        Err(_) => return,
    };
    let provider = Aes256GcmProvider::new(&[0x42; 32]).expect("fixed test key is valid");
    let sealed = provider.seal(original_context.as_bytes(), plaintext)
        .expect("bounded input can be sealed");

    let mutation_index = usize::from(mutation_selector) % scope.len();
    scope[mutation_index] ^= 0x01;
    let mutated_context = KeyContext::new(KeyPurpose::DataEncryptionKey, &scope)
        .expect("mutated non-empty scope is valid");
    assert_ne!(original_context, mutated_context);
    assert_eq!(
        provider.open(mutated_context.as_bytes(), &sealed),
        Err(CryptoError::AuthenticationFailed)
    );
});
