# ADR-0010: Testing strategy and security evidence

- **Status:** Accepted requirement in the owner-approved architecture baseline.
- **Source decision:** Original Ferrum architecture ADR-0010, baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community implementation and release evidence.

## Decision

The test strategy includes unit tests, property tests (proptest), fuzzing (cargo-fuzz), end-to-end integration, failure injection, concurrency testing (loom where appropriate), Miri where applicable, negative security tests, Criterion benchmarks, interoperability tests and cryptographic known-answer tests (KAT) plus applicable Wycheproof vectors.

The target is at least 90% measured coverage for `crypto`, `seal`, `policy`, `auth` and `audit`. Coverage does not replace meaningful test cases or review.

The planned CI quality gates include formatting, clippy with warnings denied, tests, dependency policy/audit, coverage and fuzz smoke tests. Reproducible builds, SBOM, artifact signing and provenance are required at their relevant build/release stages.

## Consequences

Tests must not be weakened or removed merely to obtain a green pipeline. Flaky or excluded tests and their reasons must be documented. Every security claim must link to reproducible evidence; passing CI is not an external security audit.


## Phase 1.4 evidence and technique boundaries

The initial `ferrum-seal` implementation records 12 unit tests for bootstrap-token lifetime/expiry/replay, FRS1 ceremony binding, rejection paths, seal/unseal root availability, concurrent transitions and panic recovery. Deterministic root-length and valid-share-subset sweeps are not a substitute for proptest. The `seal_bootstrap_transitions` libFuzzer target generates synthetic secrets/shares at runtime and mutates recovery inputs and token encodings; its committed corpus must not contain valid shares, root material or bootstrap tokens.

Exact-head PR CI evidence is recorded in [ROADMAP Phase 1.4](../../ROADMAP.md): cross-platform and MSRV validation, Miri for the pure-Rust KMP parser, and bounded fuzz smoke campaigns. Miri does not exercise AWS-LC FFI or establish memory safety of external code. No seal-specific Loom model, measured coverage result, Criterion benchmark, durable-store failure injection, or service-level crash/restart test is claimed in this phase. Add these techniques when the relevant synchronization/storage/service boundaries exist, or document a reviewed reason for any future exclusion.


## Phase 1.4 root-quorum and audit tests

The seal controller now requires an explicitly configured `RootQuorumPolicy`; there is no `Default`. The owner-approved configuration is 2-of-3 for generate-root, root rotation and root revocation. Unit coverage rejects absent/invalid policy, fewer than M shares, duplicate participants, modified share payloads and shares from another FRS1 ceremony; it accepts two distinct valid shares. The root-quorum fuzz target generates synthetic FRS1 shares at runtime and exercises the same positive and negative paths. It does not persist valid fragments or emit them to logs/artifacts.

Derived-credential revocation uses a caller-provided audit sink, does not require root fragments, records request and outcome events with a domain-separated credential-reference fingerprint, and does not invoke the revocation callback when the initial audit write fails. Durable audit delivery and atomic audit/state mutation remain service/storage integration requirements.
