# ferrum-recovery

Phase 1.3 offline root recovery primitives.

- Shamir sharing uses the audited-upstream `vsss-rs` GF(256) implementation, pinned to 6.0.1 with only `std` and `zeroize` features enabled.
- Default policy is 5 shares / 3 required; both are configurable. Policies below 2-of-n and more than 255 shares are rejected.
- FRS1 carries a versioned header, ceremony identifier, public policy, original secret length, an integrity tag and one raw Shamir share.
- A fresh random HMAC-SHA-256 verification key is itself included in the Shamir secret. Recovery verifies the combined result before returning any root bytes. A corrupted share therefore fails closed rather than silently yielding wrong root material.
- Share bytes are held in zeroizing allocations and never implement serialization frameworks, logging, persistence, or service storage. The explicit byte accessor is only for controlled offline custodian handoff.
- The crate has no service, network, filesystem, database or logging dependency. Its caller must keep shares offline and transfer them to custodians out of band.

The integrity tag authenticates the ceremony header and reconstructed root using a key protected by the same threshold scheme. It is not a digital signature, does not identify a custodian, and does not provide per-share public verifiability. Shamir's confidentiality threshold remains the primary share protection. Transport and physical custody are covered by the ceremony runbook.

This implementation does not implement bootstrap, seal/unseal, generate-root quorum, backup/restore, AWS KMS, storage-barrier encryption or production ceremony UI. The exact generate-root quorum is a later pending owner decision and is not inferred here.
