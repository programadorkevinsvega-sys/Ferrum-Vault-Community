# ADR-0024: Unsealer port and optional AWS KMS adapter

- **Status:** Owner-approved on 2026-11-13.
- **Scope:** Community root-unseal boundary and optional external provider integration.

## Decision

The seal controller depends on an object-safe asynchronous Unsealer port, not a cloud SDK or provider implementation.

The mandatory default adapter is Shamir with an exact 2-of-3 policy. Bootstrap binds only an exact 2-of-3 FRS1 ceremony and verifies its integrity. One share, duplicates, corrupted shares, mixed ceremonies, mismatched ceremony identifiers and other policies are rejected. The general offline recovery crate retains its separate 5-of-3 default; that default is not an unseal fallback.

The default SealController::unseal path always invokes ShamirUnsealer. An alternate Unsealer can be invoked only through an explicit provider-selection call. Provider failure, denial, timeout, invalid configuration, wrong key/version, invalid ciphertext or context mismatch leaves the controller Sealed. The controller never silently switches providers. Manual Shamir recovery after an alternate-provider failure is a separate operator action.

AWS KMS is optional, behind the `aws-kms` feature, and disabled by default. The Ferrum core does not link an AWS SDK, resolve AWS credentials or choose a region. The host application injects the KMS API bridge and owns the SDK and credentials. The adapter binds ciphertext to a SHA-256 fingerprint of canonical FVC1 context containing tenant=root, purpose=seal-root and the configured public ceremony identifier. KMS encryption context is non-secret and appears in plaintext in CloudTrail, so only the digest is sent.

## Separate root-operation authorization

Auto-unseal does not grant root-operation authority. `generate-root`, root rotation and root revocation continue to require the separately configured RootQuorumPolicy(2, 3). Missing or invalid root-quorum configuration fails closed. A successful KMS Decrypt cannot create, rotate or revoke the root through the quorum-protected operation gate. Derived-credential revocation remains no-quorum but audited.

## Threats and operational risks

A principal with `kms:Decrypt` permission on the configured symmetric KMS key and access to the wrapped-root ciphertext can obtain the root and unseal the controller without presenting Shamir shares. This is an alternate trust path and weakens the custody separation provided by Shamir. Treat `kms:Decrypt` as a high-impact privilege: restrict it to a dedicated runtime identity, constrain it with expected encryption-context policy conditions where possible, monitor Decrypt events and protect CloudTrail. Do not grant this permission to broad operator or application roles by default.

KMS outages, access denial, throttling, timeout, disabled/deleted keys, wrong key/version, corrupted ciphertext or context mismatch leave the controller Sealed. Recovery via Shamir must be explicitly initiated; no automatic local-key or provider fallback is permitted.

The KMS client abstraction is tested using an in-memory fake with synthetic roots and no credentials or live AWS calls. The optional feature is a transport bridge, not a claim that AWS account policy, credential issuance, network availability or production integration has been validated.

Wrapped-root metadata is not yet persisted or restart-safe. Durable encoding, atomic storage, bootstrap persistence and recovery after process restart remain Phase 1.7 scope.

## Consequences

Community remains usable without AWS. The Shamir path is the mandatory baseline and AWS KMS is an optional integration. Other providers can implement the same Unsealer port without changing the core controller.
