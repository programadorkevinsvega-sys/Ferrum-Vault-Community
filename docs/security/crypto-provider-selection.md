# Phase 1.1 — Cryptographic provider selection and evidence

## Decision

This implementation follows owner-approved ADR-0013 without changing it:

- aws-lc-rs 1.19.0 is the primary provider.
- AWS-LC provides AES-256-GCM.
- The crate is pinned to exactly =1.19.0; transitive dependencies are locked in the workspace Cargo.lock.
- The non-fips Cargo feature is selected explicitly and default features are disabled.
- No RustCrypto fallback is added because the approved algorithm is available in the primary provider.
- No FIPS certification or validated operating mode is claimed.

## Maintenance and upstream review

The selected release is the current upstream release used for this implementation. The upstream Rust wrapper repository is actively maintained and publishes versioned releases. The exact selected source is the v1.19.0 tag in aws/aws-lc-rs.

The upstream package manifest declares ISC AND (Apache-2.0 OR ISC). Its non-FIPS build requires a C/C++ compiler; upstream documentation states that CMake, bindgen and Go are not required for the default non-FIPS path. The integration intentionally disables default features and opts into non-fips only.

## Platform evaluation

The Rust provider CI matrix compiles, lints and tests the adapter on:

- Linux x86_64;
- Linux aarch64;
- macOS; and
- Windows.

The production server support policy remains Linux x86_64/aarch64. macOS and Windows are development/CLI platforms, not supported production server targets. The CI results are linked to the implementation PR; they do not establish support for untested targets.

## Known-answer and negative testing

Two AES-256-GCM KAT cases use a 256-bit key, 96-bit IV and full 128-bit tag:

1. Empty plaintext and empty AAD.
2. One 16-byte all-zero plaintext block and empty AAD.

The tests verify both seal output (ciphertext and tag) and successful opening.

## Wycheproof coverage

The test fixture is copied from C2SP Wycheproof testvectors_v1/aes_gcm_test.json at commit 65ca494727a52944c204441c860b039e6786b99b (blob 223f53cad33d78013ed635d94889836c036e1d58). It contains 316 corpus cases overall. This phase applies the approved AES-256-GCM profile only: 256-bit key, 96-bit IV and 128-bit tag. That profile has 66 cases: 39 valid and 27 invalid.

All valid cases must reproduce exact ciphertext and tag and decrypt to the expected plaintext. All invalid cases must fail authentication. Other key sizes, IV lengths and tag profiles are not silently treated as Ferrum's approved profile.

## Performance evaluation

Criterion benchmarks cover encryption and decryption for 64-byte, 1-KiB, 16-KiB and 1-MiB payloads. The baseline is provider-specific and runner-dependent. Do not convert hosted-runner timings into a hard performance SLO. For comparative performance claims, record CPU model, OS, Rust toolchain, provider version, sample interval and benchmark artifact, and compare against the same controlled environment.

## Verification boundary

This phase demonstrates correct provider integration for its selected algorithm/profile. It does not complete the barrier format, canonical AAD encoder, key management, nonce-budget/rotation controls, memory protection, seal lifecycle, KMS integration, storage or independent cryptographic review.
