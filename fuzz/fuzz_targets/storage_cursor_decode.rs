#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ferrum_storage::decode_cursor(b"kv/", data);
    let _ = ferrum_storage::decode_versioned(data);
});
