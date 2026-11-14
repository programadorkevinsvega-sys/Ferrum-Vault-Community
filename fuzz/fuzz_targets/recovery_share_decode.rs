#![no_main]

use ferrum_recovery::RecoveryShare;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(share) = RecoveryShare::decode(data) {
        assert_eq!(share.as_bytes(), data);
        assert!((1..=share.policy().share_count()).contains(&share.participant_id()));
    }
});
