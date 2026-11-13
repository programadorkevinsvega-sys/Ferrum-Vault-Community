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
