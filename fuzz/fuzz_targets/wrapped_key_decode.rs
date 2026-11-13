#![no_main]
use libfuzzer_sys::fuzz_target;
use ferrum_crypto::kmp::WrappedKey;

fuzz_target!(|data: &[u8]| {
    if let Ok(wrapped) = WrappedKey::decode(data) {
        assert_eq!(wrapped.encode().as_slice(), data);
    }
});
