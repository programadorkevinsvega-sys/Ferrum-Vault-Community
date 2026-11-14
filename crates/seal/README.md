# ferrum-seal

Phase 1.4 process-local seal lifecycle and bootstrap state machine.

## Implemented behavior

- States are Uninitialized, Sealed and Unsealed. All transitions are serialized by a mutex and protected with a generation check across expensive recovery work.
- Bootstrap issues a 256-bit token from AWS-LC's system randomness. The controller retains only a domain-separated SHA-256 verifier; the token type is non-Clone, non-serializable and redacted in Debug.
- The token lifetime is mandatory and positive. It uses Rust's monotonic Instant clock; there is no implicit TTL or wall-clock dependency.
- Bootstrap accepts only a threshold set of valid FRS1 shares from one ceremony. Recovery verifies the FRS1 integrity tag. The controller retains only the public random ceremony identifier, never the reconstructed root or recovery shares.
- Unseal accepts only the same recovery ceremony. The recovered root is held in a Zeroizing buffer and exposed only through a scoped closure.
- Seal transitions back to Sealed and drops the active root buffer. Wrong tokens, expired credentials, replay, wrong ceremonies, insufficient shares and concurrent stale transitions fail closed.

## Explicit limitations

This crate is a process-local state machine, not a durable seal service. Bootstrap token state, the ceremony identifier and lifecycle generation are volatile and are lost when the process exits. Do not use this controller as a production persistence boundary or across multiple service processes. Phase 1.7 must add a durable repository with atomic compare-and-swap/transaction semantics before service integration.

The crate does not implement an HTTP/API layer, audit persistence, throttling/rate limiting, KMP key hierarchy orchestration, the Phase 1.5 AWS KMS auto-unseal adapter, barrier encryption or backup/restore. It does not export the recovered root except through the scoped callback, but callers can still copy bytes inside that callback; zeroization is best-effort and is not an absolute memory-protection guarantee.

The generate-root workflow is deliberately not implemented. ADR-0014 leaves its exact quorum pending an owner decision. No default, threshold or bypass is supplied by this crate.

See [the seal lifecycle security notes](../../docs/security/seal-lifecycle.md).


## Root-operation quorum

The controller has no default privileged-operation quorum. The owner-approved policy is explicitly configured as `RootQuorumPolicy::new(2, 3)` and applied to generate-root, root rotation and root revocation. The FRS1 root-share policy must match that exact configuration. Missing/invalid configuration, fewer than two shares, duplicates, corruption and mixed ceremonies fail closed. The generic recovery crate's 5-of-3 default is separate and is not a fallback.

Use `with_root_quorum` as the common authorization gate; it validates the fragment set, drops reconstructed material before the callback and gives the callback only public operation context. The callback runs under the controller lock and must not re-enter it. This is a process-local authorization primitive; durable root mutation and persistent audit are not implemented here.

Derived-credential revocation does not use root quorum. Route it through `revoke_derived_credential` with a caller-provided audit sink. The raw credential reference is not emitted; only a domain-separated fingerprint appears in audit events. If the initial audit write fails, the revocation callback is not executed.
