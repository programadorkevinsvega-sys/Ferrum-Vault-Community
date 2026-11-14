#![no_main]

use ferrum_recovery::{RecoveryPolicy, RecoveryShare, generate_secret_shares};
use ferrum_seal::{BootstrapToken, SealController, SealStatus};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

fn copy_share(share: &RecoveryShare) -> RecoveryShare {
    RecoveryShare::decode(share.as_bytes()).expect("generated share remains valid")
}

fuzz_target!(|data: &[u8]| {
    let controller = SealController::new();

    // The parser must reject arbitrary lengths and invalid credentials without
    // changing the initial state. A 32-byte candidate is still untrusted.
    if let Ok(candidate) = BootstrapToken::from_bytes(data) {
        assert!(controller.bootstrap(&candidate, &[]).is_err());
        assert_eq!(controller.snapshot().status, SealStatus::Uninitialized);
    }

    // Generate all secrets and shares at runtime; the corpus contains no valid
    // key, ceremony share or bootstrap credential.
    let Ok(shares) = generate_secret_shares(32, RecoveryPolicy::new(2, 3).expect("2-of-3 root policy")) else {
        return;
    };
    let Ok(token) = controller.issue_bootstrap_token(Duration::from_secs(60)) else {
        return;
    };
    if let Ok(candidate) = BootstrapToken::from_bytes(data) {
        assert!(controller.bootstrap(&candidate, &shares[..3]).is_err());
        assert!(controller.snapshot().bootstrap_pending);
    }

    let mut mutated = shares[0].as_bytes().to_vec();
    for (index, byte) in data.iter().copied().enumerate().take(mutated.len()) {
        mutated[index] ^= byte;
    }

    let mut supplied = Vec::with_capacity(3);
    if let Ok(changed) = RecoveryShare::decode(&mutated) {
        supplied.push(changed);
        supplied.push(copy_share(&shares[1]));
        supplied.push(copy_share(&shares[2]));
    } else {
        supplied.push(copy_share(&shares[1]));
        supplied.push(copy_share(&shares[2]));
    }

    let result = controller.bootstrap(&token, &supplied);
    match result {
        Ok(()) => {
            assert_eq!(controller.snapshot().status, SealStatus::Sealed);
            assert!(controller.bootstrap(&token, &supplied).is_err());
            assert!(controller.unseal(&supplied).is_ok());
            assert_eq!(controller.snapshot().status, SealStatus::Unsealed);
            assert!(controller.with_root_key(|root| root.len()).is_ok());
            assert!(controller.seal().is_ok());
            assert_eq!(controller.snapshot().status, SealStatus::Sealed);
        }
        Err(_) => {
            assert_eq!(controller.snapshot().status, SealStatus::Uninitialized);
            assert!(controller.snapshot().bootstrap_pending);
            assert!(controller.unseal(&supplied).is_err());
            assert!(controller.seal().is_err());
        }
    }
});
