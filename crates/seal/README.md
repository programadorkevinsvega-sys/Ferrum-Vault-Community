# ferrum-seal

Phase 1.4 process-local seal lifecycle plus the Phase 1.5 provider-independent unseal port.

## Implemented behavior

- States are Uninitialized, Sealed and Unsealed. All transitions are serialized by a mutex and protected with a generation check across expensive recovery work.
- Bootstrap issues a 256-bit token from AWS-LC's system randomness. The controller retains only a domain-separated SHA-256 verifier; the token type is non-Clone, non-serializable and redacted in Debug.
- The token lifetime is mandatory and positive. It uses Rust's monotonic Instant clock; there is no implicit TTL or wall-clock dependency.
- Bootstrap accepts only an exact 2-of-3 set of valid FRS1 shares from one ceremony. Recovery verifies the FRS1 integrity tag. The controller retains only the public random ceremony identifier, never the reconstructed root or recovery shares.
- The mandatory default unseal path uses Shamir 2-of-3 only. The generic offline recovery crate keeps its separate 5-of-3 default.
- The object-safe async provider port is `Unsealer`. `SealController::unseal` always selects `ShamirUnsealer`; another adapter requires an explicit `unseal_with` call and never becomes an automatic fallback.
- The optional `aws-kms` feature is disabled by default. It adds no AWS SDK or credential provider dependency to the Ferrum core; the host application injects its SDK client.
- Seal transitions back to Sealed and drops the active root buffer. Wrong tokens, expired credentials, replay, wrong ceremonies, insufficient shares and concurrent stale transitions fail closed.

## Explicit limitations

This crate is a process-local state machine, not a durable seal service. Bootstrap token state, the ceremony identifier and lifecycle generation are volatile and are lost when the process exits. Do not use this controller as a production persistence boundary or across multiple service processes. Phase 1.7 must add a durable repository with atomic compare-and-swap/transaction semantics before service integration.

The crate does not implement an HTTP/API layer, audit persistence, throttling/rate limiting, KMP key hierarchy orchestration, durable provider configuration, barrier encryption or backup/restore. It does not export the recovered root except through the scoped callback, but callers can still copy bytes inside that callback; zeroization is best-effort and is not an absolute memory-protection guarantee.

The service-level generate-root handler/token-issuance flow is not implemented by this crate. The crate supplies the approved 2-of-3 authorization gate for generate-root, root rotation and root revocation. There is no automatically installed quorum policy; the caller must explicitly configure it. Durable root mutation and a production command/API remain outside this phase.

See [the seal lifecycle security notes](../../docs/security/seal-lifecycle.md).


## Root-operation quorum

The controller has no default privileged-operation quorum. The owner-approved policy is explicitly configured as `RootQuorumPolicy::new(2, 3)` and applied to generate-root, root rotation and root revocation. The FRS1 root-share policy must match that exact configuration. Missing/invalid configuration, fewer than two shares, duplicates, corruption and mixed ceremonies fail closed. The generic recovery crate's 5-of-3 default is separate and is not a fallback.

Use `with_root_quorum` as the common authorization gate; it validates the fragment set, drops reconstructed material before the callback and gives the callback only public operation context. The callback runs under the controller lock and must not re-enter it. This is a process-local authorization primitive; durable root mutation and persistent audit are not implemented here.

Derived-credential revocation does not use root quorum. Route it through `revoke_derived_credential` with a caller-provided audit sink. The raw credential reference is not emitted; only a domain-separated fingerprint appears in audit events. If the initial audit write fails, the revocation callback is not executed.


## Phase 1.5 provider behavior

The mandatory default is the Shamir adapter with exactly two of three shares. It rejects one share, duplicate participants, corruption, mixed ceremonies, a mismatched ceremony id and every other policy (including the generic 5-of-3 recovery default).

The optional `aws-kms` feature is disabled by default. It exposes an injected KMS API bridge; the core does not load AWS credentials or link an AWS SDK. The host application supplies its own SDK client and explicitly chooses the KMS adapter. There is no automatic fallback between providers. Any KMS error, timeout, missing/invalid configuration, key mismatch, version mismatch or context mismatch leaves the controller Sealed. Manual Shamir recovery is a separate operator action.

KMS ciphertext is bound to a SHA-256 fingerprint of the canonical FVC1 seal-root context, including the public ceremony identifier. Only this digest is sent as KMS encryption context. See [the auto-unseal threat and recovery notes](../../docs/security/auto-unseal.md).

Even when KMS auto-unseal is selected, `generate-root`, root rotation and root revocation still require the independently configured 2-of-3 RootQuorumPolicy. A principal with `kms:Decrypt` and access to the wrapped root can bypass the Shamir unseal ceremony, but that does not authorize these root operations. Treat `kms:Decrypt` as a high-impact privilege, restrict and audit it.
