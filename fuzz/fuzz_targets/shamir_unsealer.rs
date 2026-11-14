#![no_main]

use ferrum_recovery::{RecoveryPolicy, RecoveryShare, generate_secret_shares};
use ferrum_seal::ShamirUnsealer;
use libfuzzer_sys::fuzz_target;

fn copy_share(share: &RecoveryShare) -> RecoveryShare {
    RecoveryShare::decode(share.as_bytes()).expect("runtime-generated share is valid")
}

fuzz_target!(|data: &[u8]| {
    // Root material and valid shares are generated at runtime only. The corpus
    // contains arbitrary bytes, never valid ceremony fragments or root keys.
    let policy = RecoveryPolicy::new(2, 3).expect("mandatory Shamir policy");
    let Ok(shares) = generate_secret_shares(32, policy) else {
        return;
    };
    let ceremony_id = shares[0].ceremony_id();

    assert!(ShamirUnsealer::unseal_shares(ceremony_id, &shares[..2]).is_ok());
    assert!(ShamirUnsealer::unseal_shares(ceremony_id, &shares[..1]).is_err());

    let duplicate = [copy_share(&shares[0]), copy_share(&shares[0])];
    assert!(ShamirUnsealer::unseal_shares(ceremony_id, &duplicate).is_err());

    let mut corrupted_bytes = shares[0].as_bytes().to_vec();
    for (index, byte) in data.iter().copied().enumerate().take(corrupted_bytes.len()) {
        corrupted_bytes[index] ^= byte;
    }
    if let Ok(corrupted) = RecoveryShare::decode(&corrupted_bytes) {
        let damaged = [corrupted, copy_share(&shares[1])];
        assert!(ShamirUnsealer::unseal_shares(ceremony_id, &damaged).is_err());
    }

    let Ok(other_ceremony) = generate_secret_shares(32, policy) else {
        return;
    };
    let mixed = [copy_share(&shares[0]), copy_share(&other_ceremony[1])];
    assert!(ShamirUnsealer::unseal_shares(ceremony_id, &mixed).is_err());

    // The general recovery library's 5-of-3 default is not a root-unseal
    // fallback and must always be rejected by this adapter.
    let Ok(generic) = generate_secret_shares(32, RecoveryPolicy::default()) else {
        return;
    };
    assert!(ShamirUnsealer::unseal_shares(generic[0].ceremony_id(), &generic[..3]).is_err());

    if let Ok(untrusted) = RecoveryShare::decode(data) {
        let attempted = [untrusted, copy_share(&shares[0])];
        assert!(ShamirUnsealer::unseal_shares(ceremony_id, &attempted).is_err());
    }
});
