# Auto-unseal threat model and recovery procedure (Phase 1.5)

## Security model

The seal controller depends on the object-safe asynchronous `Unsealer` port. Its mandatory default implementation is Shamir 2-of-3. The controller does not depend on a cloud provider or cloud SDK.

The generic offline recovery crate retains its separate 5-of-3 default for recovery utilities. It must not be treated as an unseal policy or fallback. Bootstrap and default unseal accept only exact 2-of-3 FRS1 shares bound to one ceremony id, with distinct participants and a valid integrity tag.

An alternate adapter is never auto-detected. It must be selected explicitly by the caller. A provider failure never switches the controller to another provider.

## Optional AWS KMS adapter

The `aws-kms` feature is opt-in and disabled by default. It contains only an injected client bridge; it does not add an AWS SDK or credential provider to the Ferrum core. The host application is responsible for constructing the real SDK client, selecting the region, acquiring credentials, setting network timeouts and enforcing IAM/key policies.

The adapter uses a symmetric KMS key. The KMS encryption context contains a SHA-256 fingerprint of canonical FVC1 context for tenant `root`, purpose `seal-root` and the expected public 128-bit ceremony identifier. Raw root material, share bytes, tokens and caller scope are not sent as encryption-context metadata. KMS encryption context is non-secret and is recorded in plaintext by AWS; never put secrets there.

The ciphertext envelope records a configured key identifier and logical envelope version. The configured values must be present and valid. A mismatch, empty ciphertext/plaintext, access denied, invalid ciphertext, disabled/deleted key, throttling, timeout or provider failure leaves the controller Sealed.

## Critical privilege risk: kms:Decrypt

A principal that has `kms:Decrypt` on the configured key and can obtain the wrapped-root ciphertext can decrypt the root and unseal the system without presenting Shamir shares. This is an alternate trust path that bypasses the manual Shamir ceremony for unseal. Do not describe it as equivalent to Shamir quorum custody.

Required operational controls for deployments that explicitly enable this adapter:

- Grant `kms:Decrypt` only to a dedicated runtime identity. Do not grant it to broad operators, general application roles, CI identities or user-facing workloads.
- Restrict key policy and IAM conditions to the exact encryption-context key/value expected by the deployment. Review grants and cross-account access.
- Keep `kms:Encrypt` separate from `kms:Decrypt` where operationally possible. Limit who can change the key policy or create grants.
- Monitor and alert on Decrypt, policy changes, grant creation, key disablement and deletion. Protect the CloudTrail account/logging boundary.
- Use a finite client-side timeout, bounded retries, jittered backoff and concurrency limits. Cancellation leaves outcome unknown; never infer that a remote KMS request was rolled back.
- Document key disablement/deletion, account lockout and regional outage as sealed-state incidents. Do not cache plaintext roots across seal or process restart.

## Root-operation quorum is independent

KMS unseal does not create, configure or satisfy root-operation quorum. `generate-root`, root rotation and root revocation continue to require the separately configured `RootQuorumPolicy::new(2, 3)` gate and two distinct valid fragments from the bound 2-of-3 ceremony. Missing/invalid configuration, one share, duplicate shares, corrupt shares, mixed ceremonies or wrong ceremony fail closed even after successful KMS unseal.

Derived-credential revocation remains a separate operation that requires an audit record, not root shares.

## Recovery after provider failure

1. Treat access denied, timeout, unavailable KMS, disabled/deleted key, bad metadata and authentication errors as a sealed system. Preserve diagnostic error class but never log credentials, ciphertext, plaintext, root bytes, shares or bootstrap tokens.
2. Do not configure a local plaintext key, cached root or automatic provider fallback.
3. An authorized operator explicitly initiates the documented Shamir 2-of-3 recovery ceremony using two distinct custodians and shares from the bound ceremony.
4. Verify all supplied shares and the FRS1 integrity tag. If the configured ceremony cannot be reconstructed, stop and invoke the offline recovery/incident runbook; do not create a new root or silently bind another ceremony.
5. After unseal, investigate KMS/IAM/key lifecycle logs, restore only the approved key access path and verify that root-operation quorum remains independently configured.
6. If the key is permanently unavailable, use the separately approved offline root recovery and rotation procedure. Any root rotation still passes the explicit 2-of-3 operation gate and requires durable transactional integration before production use.

## Verification and limitations

The KMS adapter is tested with a fake in-memory client and synthetic roots; CI performs no live AWS calls and uses no real credentials. Tests cover context binding, wrong ceremony, key metadata mismatch, access denial, timeout mapping, fail-closed behavior, explicit manual Shamir recovery and independent root-operation quorum. These tests do not validate real AWS IAM policy, credentials, network conditions, CloudTrail configuration or production availability.

Wrapped-root metadata and controller state are not durable or restart-safe. Their atomic persistence belongs to Phase 1.7. Do not treat the Phase 1.5 in-memory types as a production deployment or backup format.
