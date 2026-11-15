#![no_main]

use std::collections::HashSet;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use ferrum_crypto::barrier::{
    BarrierCipher, BarrierEnvelope, BarrierKeyring, CanonicalPath, NonceBudget,
    NonceBudgetConfig, NonceLedgerError, NonceReservation, NonceUsageLedger,
    VersionedDataKey,
};
use ferrum_crypto::kmp::KeyId;
use libfuzzer_sys::fuzz_target;

#[derive(Default)]
struct FuzzLedger {
    high_water: Mutex<u64>,
}

impl NonceUsageLedger for FuzzLedger {
    fn reserve(
        &self,
        _key_id: &KeyId,
        _key_version: u64,
        config: NonceBudgetConfig,
    ) -> Result<NonceReservation, NonceLedgerError> {
        let mut high_water = self
            .high_water
            .lock()
            .map_err(|_| NonceLedgerError::Unavailable)?;
        if *high_water == 0 {
            *high_water = 1;
        }
        let end = high_water
            .checked_add(config.reservation_block_size().get())
            .ok_or(NonceLedgerError::CounterExhausted)?;
        let reservation = NonceReservation::new(*high_water, end)?;
        *high_water = end;
        Ok(reservation)
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // These values are generated from fuzz input only. They are not production
    // defaults and do not resolve the owner's pending numeric policy.
    let block = u64::from((data[0] % 8) + 1);
    let threshold = block + u64::from(data[1] % 32);
    let Ok(config) = NonceBudgetConfig::new(
        NonZeroU64::new(block).expect("block is nonzero"),
        NonZeroU64::new(threshold).expect("threshold is nonzero"),
    ) else {
        return;
    };

    let key_id = KeyId::new("fuzz/barrier").expect("static key id is valid");
    let keyring = Arc::new(
        BarrierKeyring::new(
            key_id,
            1,
            vec![VersionedDataKey::new(1, [0x42; 32]).expect("test key is valid")],
        )
        .expect("test keyring is valid"),
    );
    let budget = Arc::new(NonceBudget::new(config, Arc::new(FuzzLedger::default())));
    let barrier = BarrierCipher::new(keyring, budget);
    let path = CanonicalPath::new(b"fuzz/nonces".to_vec()).expect("static path is valid");
    let mut nonces = HashSet::new();
    let mut accepted = 0_u64;

    for _ in 0..128 {
        match barrier.seal(&path, b"synthetic fuzz plaintext") {
            Ok(encoded) => {
                let envelope = BarrierEnvelope::decode(&encoded)
                    .expect("barrier output is a canonical FBE1 envelope");
                assert_eq!(envelope.key_version(), 1);
                // Collision is astronomically unlikely at this bounded test
                // volume; the persistent ledger counter is checked separately
                // by deterministic concurrent unit tests.
                let nonce = encoded_nonce(&envelope);
                assert!(nonces.insert(nonce), "random nonce repeated under one test key");
                accepted += 1;
                assert!(accepted <= threshold);
            }
            Err(ferrum_crypto::barrier::BarrierError::RotationRequired) => break,
            Err(error) => panic!("unexpected fail-closed barrier error: {error}"),
        }
    }
});

fn encoded_nonce(envelope: &BarrierEnvelope) -> [u8; 12] {
    // The nonce is intentionally not exposed by the production envelope
    // accessor; decode the fixed public FBE1 field offset for this fuzz-only
    // invariant (magic + versions + key id + key version).
    // Fuzz key id "fuzz/barrier" has 12 bytes.
    let encoded = envelope.encode();
    let offset = 4 + 2 + 2 + "fuzz/barrier".len() + 8;
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&encoded[offset..offset + 12]);
    nonce
}
