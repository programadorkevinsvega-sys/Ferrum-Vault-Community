#![no_main]

use ferrum_recovery::{
    RecoveryPolicy, RecoveryShare, recover_secret, split_secret_with_rng,
};
use libfuzzer_sys::fuzz_target;
use rand::rngs::StdRng;
use rand_core::SeedableRng;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Fuzz-only deterministic randomness; never used by production ceremony code.
    let secret_len = data.len().min(2048);
    let secret = &data[..secret_len];
    let mut rng = StdRng::from_seed([0xA7; 32]);
    let Ok(mut shares) = split_secret_with_rng(secret, RecoveryPolicy::default(), &mut rng) else {
        return;
    };

    let selected = usize::from(data[0]) % shares.len();
    let original = shares.remove(selected);
    let mut mutated = original.as_bytes().to_vec();
    let position = if data.len() > 1 {
        usize::from(data[1]) % mutated.len()
    } else {
        mutated.len() - 1
    };
    mutated[position] ^= 0x01;

    if let Ok(mutated_share) = RecoveryShare::decode(&mutated) {
        shares.push(mutated_share);
        if let Ok(recovered) = recover_secret(&shares) {
            assert_eq!(recovered.as_slice(), secret);
        }
    }
});
