#![no_main]

use ferrum_recovery::{RecoveryPolicy, RecoveryShare, generate_secret_shares};
use ferrum_seal::{RootQuorumOperation, RootQuorumPolicy, SealController, SealError};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

fn copy_share(share: &RecoveryShare) -> RecoveryShare {
    RecoveryShare::decode(share.as_bytes()).expect("runtime-generated share is valid")
}

fuzz_target!(|data: &[u8]| {
    // All root material and FRS1 fragments are generated at runtime. Nothing
    // sensitive or reconstructable is stored in the corpus or emitted.
    let policy = RecoveryPolicy::new(2, 3).expect("owner-approved 2-of-3 policy");
    let Ok(shares) = generate_secret_shares(32, policy) else {
        return;
    };
    let controller = SealController::new();
    let Ok(quorum) = RootQuorumPolicy::new(2, 3) else {
        return;
    };
    if controller.configure_root_quorum(quorum).is_err() {
        return;
    }
    let Ok(token) = controller.issue_bootstrap_token(Duration::from_secs(60)) else {
        return;
    };
    if controller.bootstrap(&token, &shares[..2]).is_err() {
        return;
    }

    for operation in [
        RootQuorumOperation::GenerateRoot,
        RootQuorumOperation::RotateRoot,
        RootQuorumOperation::RevokeRoot,
    ] {
        assert_eq!(
            controller.with_root_quorum(operation, &shares[..1], |_| ()),
            Err(SealError::RootQuorumRejected)
        );
        assert!(controller
            .with_root_quorum(operation, &shares[..2], |_| true)
            .expect("two valid distinct shares must authorize"));

        let duplicate = [copy_share(&shares[0]), copy_share(&shares[0])];
        assert_eq!(
            controller.with_root_quorum(operation, &duplicate, |_| ()),
            Err(SealError::RootQuorumRejected)
        );

        let mut damaged_bytes = shares[0].as_bytes().to_vec();
        damaged_bytes[65] ^= 1;
        if let Ok(damaged) = RecoveryShare::decode(&damaged_bytes) {
            let damaged_set = [damaged, copy_share(&shares[1])];
            assert_eq!(
                controller.with_root_quorum(operation, &damaged_set, |_| ()),
                Err(SealError::RootQuorumRejected)
            );
        }
    }

    let Ok(other_set) = generate_secret_shares(32, policy) else {
        return;
    };
    let mixed = [copy_share(&shares[0]), copy_share(&other_set[1])];
    assert_eq!(
        controller.with_root_quorum(RootQuorumOperation::RotateRoot, &mixed, |_| ()),
        Err(SealError::RootQuorumRejected)
    );

    // Exercise the strict parser with arbitrary bytes without allowing them to
    // become accepted quorum members.
    if let Ok(untrusted) = RecoveryShare::decode(data) {
        let attempted = [untrusted, copy_share(&shares[0])];
        assert!(controller
            .with_root_quorum(RootQuorumOperation::GenerateRoot, &attempted, |_| ())
            .is_err());
    }
});
