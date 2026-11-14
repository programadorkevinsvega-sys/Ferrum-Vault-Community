# Auto-unseal threat model and AWS KMS integration (Phase 1.5)

## Provider-independent security model

The seal controller depends on the object-safe asynchronous `Unsealer` port. Its mandatory default implementation is Shamir 2-of-3. The controller does not depend on a cloud provider or cloud SDK.

The generic offline recovery crate retains its separate 5-of-3 default for recovery utilities. It is not an unseal policy or fallback. Bootstrap and default unseal accept only exact 2-of-3 FRS1 shares bound to one ceremony id, with distinct participants and a valid integrity tag.

An alternate adapter is never auto-detected. It must be selected explicitly by the caller. A provider failure never switches the controller to another provider.

## Official AWS SDK adapter

The `aws-kms` feature is opt-in and disabled by default. When enabled, the feature uses the official AWS SDK for Rust crates `aws-config` and `aws-sdk-kms`; these crates are not in the default feature graph and do not become dependencies of `ferrum-crypto`, `ferrum-recovery` or the provider-neutral unsealer port.

Construct the adapter with:

```rust
let unsealer =
    AwsKmsUnsealer::<AwsSdkKmsApi>::from_environment(full_key_arn, envelope_version).await?;
```

The constructor requires a full customer-managed key ARN, derives the region from that ARN, configures the KMS client for that exact region and calls `DescribeKey`. It rejects alias names, key IDs without an ARN, region/account mismatches, AWS-managed keys, non-symmetric keys, keys not using `ENCRYPT_DECRYPT`, and disabled keys.

The SDK uses its standard credential provider chain; the application does not pass credential strings into Ferrum. Supported environment setups include environment credentials, named/shared AWS profiles (via `AWS_PROFILE`), shared configuration, web identity and workload/instance role credentials (such as ECS/EKS and EC2). Prefer short-lived IAM role credentials. Do not embed static keys in source, environment files committed to the repository, Docker build arguments or CI variables. The SDK's region is deliberately pinned from the key ARN; an independently configured `AWS_REGION` mismatch is rejected by the live verification script.

The AWS adapter calls `DescribeKey`, `Encrypt` and `Decrypt`. KMS ciphertexts are bound to a SHA-256 fingerprint of the canonical FVC1 context for tenant `root`, purpose `seal-root` and the expected public 128-bit ceremony identifier. The exact same context is sent on Encrypt and Decrypt. The KMS encryption-context value is non-secret metadata and is visible in CloudTrail; the raw root, shares, bootstrap token and plaintext are never placed in the context. KMS Encrypt accepts at most 4,096 plaintext bytes; the adapter rejects larger values before the request.

The constructor does not create a key, alter a key policy, create IAM roles or assign grants. Provision these separately using the examples below. If DescribeKey, Encrypt or Decrypt is denied, the configured key is unavailable, the key metadata is wrong, or the context/ciphertext is invalid, the controller remains Sealed. There is no local-key or provider fallback.

## IAM role policy: least privilege

The application runtime role needs only these KMS actions on the exact configured key:

- `kms:DescribeKey` to validate key metadata during adapter construction.
- `kms:Encrypt` and `kms:Decrypt` for the wrapped root.
- No `kms:CreateKey`, `kms:PutKeyPolicy`, `kms:CreateGrant`, `kms:ScheduleKeyDeletion` or broad `kms:*` permission is required by the adapter.

Start from [the runtime-role identity policy example](aws-kms-runtime-role-policy.example.json), replace the full key ARN and attach it to the dedicated workload role. Also add the corresponding allow statement to the KMS key policy using [this key-policy statement example](aws-kms-key-policy-statement.example.json); preserve the existing key administrators and lockout-recovery statements rather than replacing the full key policy.

The example constrains the request to use exactly one encryption-context key named `FerrumContextSHA256V1`. The value is a per-ceremony SHA-256 fingerprint and therefore changes between ceremonies. The policy uses `Null:false` to require that single-valued context pair to be present and `ForAllValues:StringEquals` only with the multi-valued `kms:EncryptionContextKeys` condition key to reject any additional context keys. Do **not** place `ForAllValues` or `ForAnyValue` on `kms:EncryptionContext:FerrumContextSHA256V1`; AWS warns that a set operator on that single-valued condition can allow requests that omit the context. The exact key names and case must match the adapter.

The operator/audit identity used by the verification script separately needs `kms:GetKeyPolicy` and `cloudtrail:LookupEvents`; see [the audit-role policy example](aws-kms-audit-role-policy.example.json). Do not grant those read/audit permissions to the runtime role unless it has a separate operational need.

## Critical privilege risk: kms:Decrypt

A principal that has `kms:Decrypt` on the configured key and can obtain the wrapped-root ciphertext can decrypt the root and unseal the system without presenting Shamir shares. This is an alternate trust path that bypasses the manual Shamir ceremony for unseal. Do not describe it as equivalent to Shamir quorum custody.

Grant `kms:Decrypt` only to the dedicated runtime identity that must auto-unseal. Review key-policy principals, IAM role trust policies, grants, cross-account access and paths that could let an attacker obtain the wrapped ciphertext. Monitor Decrypt, policy changes, grant creation, key disablement and deletion. Protect CloudTrail log delivery and restrict who can change it. Do not grant this permission to broad operators, CI identities or user-facing workloads.

## Root-operation quorum remains independent

KMS unseal does not create, configure or satisfy root-operation quorum. `generate-root`, root rotation and root revocation still require the separately configured `RootQuorumPolicy::new(2, 3)` gate and two distinct valid fragments from the bound 2-of-3 ceremony. Missing/invalid configuration, one share, duplicate shares, corrupt shares, mixed ceremonies or a wrong ceremony fail closed even after successful KMS unseal.

Derived-credential revocation remains a separate operation that requires an audit record, not root shares.

## Live integration, IAM and CloudTrail verification

From a controlled workstation or workload with AWS CLI v2, `jq`, Rust/Cargo and the intended AWS identity:

```bash
export FERRUM_AWS_KMS_KEY_ARN='arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_UUID'
export FERRUM_AWS_KMS_RUNTIME_PRINCIPAL_ARN='arn:aws:iam::ACCOUNT_ID:role/FerrumVaultRuntime'
# Optional: profile used by the Rust SDK runtime
export FERRUM_AWS_KMS_RUNTIME_PROFILE='ferrum-runtime'
# Optional: separate profile for IAM simulation, key-policy and CloudTrail reads
export FERRUM_AWS_KMS_AUDIT_PROFILE='security-auditor'
scripts/aws-kms-live-verify.sh
```

If the audit profile is omitted, the same CLI identity must be able to call `kms:GetKeyPolicy` and `cloudtrail:LookupEvents`. The SDK runtime identity must be able to call `kms:DescribeKey`, `kms:Encrypt` and `kms:Decrypt` on the configured key. The script:

1. Resolves the KMS region from the full key ARN and rejects a conflicting `AWS_REGION`.
2. Records the audit identity ARN and retrieves/validates the actual default key policy (without printing or changing it).
3. Describes the key and verifies exact ARN, `SYMMETRIC_DEFAULT`, `ENCRYPT_DECRYPT` and `Enabled`.
4. Runs the official Rust SDK example, which generates a new random 32-byte synthetic root and random ceremony id, performs Encrypt and Decrypt, compares the returned plaintext in memory and prints only the context digest and public metadata.
5. Simulates the runtime IAM principal for `DescribeKey`, `Encrypt` and `Decrypt` using the exact context key-set and per-run digest; then queries regional CloudTrail Event History for both `Encrypt` and `Decrypt`, matching the exact context fingerprint and key ARN/key ID. It waits up to three minutes for Event History propagation and fails if either event is absent.

CloudTrail Event History provides 90 days of regional management events and includes KMS activity; unlike a trail or event data store, KMS events cannot be excluded from Event History. A separately configured trail can exclude high-volume KMS events, so validate Event History or ensure the audit trail records them. The event history is per account and Region; query the Region in the KMS key ARN.

The script does not create or modify the key, key policy, IAM role, grants, CloudTrail trail or event data store. It does not test production root material. The synthetic test root exists only in process memory and is never printed, saved or added to a file. The script's CloudTrail match is evidence of the test Encrypt/Decrypt events, not proof of a complete organizational logging configuration.

## Recovery after provider failure

1. Treat access denied, timeout, unavailable KMS, disabled/deleted key, bad metadata and authentication errors as a sealed system. Preserve diagnostic error class but never log credentials, ciphertext, plaintext, root bytes, shares or bootstrap tokens.
2. Do not configure a local plaintext key, cached root or automatic provider fallback.
3. An authorized operator explicitly initiates the documented Shamir 2-of-3 recovery ceremony using two distinct custodians and shares from the bound ceremony.
4. Verify all supplied shares and the FRS1 integrity tag. If the configured ceremony cannot be reconstructed, stop and invoke the offline recovery/incident runbook; do not create a new root or silently bind another ceremony.
5. After unseal, investigate KMS/IAM/key lifecycle logs, restore only the approved key access path and verify that root-operation quorum remains independently configured.
6. If the key is permanently unavailable, use the separately approved offline root recovery and rotation procedure. Any root rotation still passes the explicit 2-of-3 operation gate and requires durable transactional integration before production use.

## Verification boundaries

CI tests use an in-memory fake and synthetic values only; they never load AWS credentials or contact a real account. Live account verification is an explicit operator-run procedure and its results must be recorded separately with the account/Region, role ARN, key ARN, event IDs and timestamp, without recording credentials or root material.

Wrapped-root metadata and controller state are not durable or restart-safe. Their atomic persistence belongs to Phase 1.7. Do not treat Phase 1.5 in-memory types as a production persistence format or declare production readiness until persistence, deployment-specific IAM/CloudTrail acceptance and service integration are complete.
