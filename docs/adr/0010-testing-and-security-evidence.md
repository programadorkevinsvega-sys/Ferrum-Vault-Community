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

The initial `ferrum-seal` lifecycle implementation records 12 unit tests for bootstrap-token lifetime/expiry/replay, FRS1 ceremony binding, rejection paths, seal/unseal root availability, concurrent transitions and panic recovery. The approved root-operation quorum and derived-credential audit helper add eight tests, bringing the current `ferrum-seal` suite to 20 passing tests on the exact PR head. Deterministic root-length and valid-share-subset sweeps are not a substitute for proptest. The `seal_bootstrap_transitions` libFuzzer target generates synthetic secrets/shares at runtime and mutates recovery inputs and token encodings; its committed corpus must not contain valid shares, root material or bootstrap tokens.

Exact-head PR CI evidence is recorded in [ROADMAP Phase 1.4](../../ROADMAP.md): cross-platform and MSRV validation, Miri for the pure-Rust KMP parser, and bounded fuzz smoke campaigns. Miri does not exercise AWS-LC FFI or establish memory safety of external code. No seal-specific Loom model, measured coverage result, Criterion benchmark, durable-store failure injection, or service-level crash/restart test is claimed in this phase. Add these techniques when the relevant synchronization/storage/service boundaries exist, or document a reviewed reason for any future exclusion.


## Phase 1.4 root-quorum and audit tests

The seal controller now requires an explicitly configured `RootQuorumPolicy`; there is no `Default`. The owner-approved configuration is 2-of-3 for generate-root, root rotation and root revocation. Unit coverage rejects absent/invalid policy, fewer than M shares, duplicate participants, modified share payloads and shares from another FRS1 ceremony; it accepts two distinct valid shares. The root-quorum fuzz target generates synthetic FRS1 shares at runtime and exercises the same positive and negative paths. It does not persist valid fragments or emit them to logs/artifacts.

Derived-credential revocation uses a caller-provided audit sink, does not require root fragments, records request and outcome events with a domain-separated credential-reference fingerprint, and does not invoke the revocation callback when the initial audit write fails. Durable audit delivery and atomic audit/state mutation remain service/storage integration requirements.


The exact implementation evidence at `762bbe3fea4e6b8d572f8688df185e21005dd5dc` is CI run [#43542327701](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43542327701) (16/16 jobs passed, including all four platforms, MSRV, Miri, nine fuzz smoke targets and public Markdown/patch gates) and Gitleaks run [#43542327705](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43542327705) (full fetched Git history/refs passed). The `root_quorum_authorization` 60-second campaign passed with runtime-generated synthetic FRS1 material. These results apply to that code commit; this section's subsequent documentation-only commit will be revalidated independently.


## Phase 1.5 unsealer verification evidence

The provider-neutral `Unsealer` port has a mandatory Shamir 2-of-3 default. Unit tests reject one share, duplicate participants, damaged FRS1 payloads, mixed/wrong ceremonies and the generic offline 5-of-3 policy. `SealController::unseal` always selects that adapter; any alternate provider is explicitly selected and a provider failure leaves the controller Sealed without automatic fallback.

The optional `aws-kms` feature is disabled by default and adds no AWS SDK or credential-provider dependency to the Community core. The adapter uses an injected client contract. Its in-memory KMS fake uses synthetic roots only and passed 34/34 tests, including context/ceremony binding, key metadata validation, AccessDenied, timeout and unavailable/failure mapping, no fallback and the independent root-operation quorum. No live AWS credentials, account or network calls were used.

Exact-head evidence at `5ac7fb8e4aeb8d5e22e2c3810fb8cb6b606d872a`: [CI run #43550638479](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43550638479) passed 18/18 jobs, including all four supported platform jobs, MSRV Rust 1.98, Miri, optional KMS fake and ten 60-second libFuzzer smoke targets. The new `shamir_unsealer` target passed. [Gitleaks run #43550638485](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43550638485) passed over fetched Git history and refs. These CI results do not validate real AWS IAM/key policies, CloudTrail setup, network resilience, production credentials or service-level restart/persistence. Durable wrapped-root storage, crash recovery and service integration remain Phase 1.7 requirements.
