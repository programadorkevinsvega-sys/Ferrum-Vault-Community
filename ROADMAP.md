# Ferrum Community roadmap

This roadmap describes the public Community edition. It records approved design direction and phase gates, not delivery dates or guarantees. Enterprise-only capabilities and private implementation plans are deliberately excluded.

## Current status

**Phase 0 — Foundations: documentation baseline in progress.** The repository now includes the initial cryptographic Cargo workspace, but it does not yet contain a complete Rust runtime, server or CLI. The public architecture decisions have been carried over into [Community ADRs](docs/adr/README.md). Phase 0 remains open until its remaining Definition of Done and owner acceptance are recorded.

**Phase 1 — Seal and encrypted storage: implementation in progress.** Subphase 1.1 (cryptographic provider, vectors, deterministic boundary tests and fuzz baseline) is implemented in [PR #10](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/10), [PR #12](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/12) and [PR #13](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/13). Subphase 1.2 is under implementation and review in this change; subphases 1.3–1.7 remain pending. The approved design inputs are in public ADRs 0001–0004 and 0013–0014. The implementation must follow the phase gates below and must not guess explicitly pending parameters.

## Phase overview

| Phase | Name | Community outcome |
|---|---|---|
| 0 | Foundations | Public architecture, threat boundaries, decision records, workspace plan, governance and CI baseline |
| 1 | Seal and encrypted storage | Cryptographic boundary, seal lifecycle, key hierarchy, barrier encryption, recovery and encrypted persistence |
| 2 | API, authentication and policy | Versioned TLS API, authentication, deny-by-default authorization and durable audit |
| 3 | PKI engine | Certificate authority workflows, issuance, revocation and interoperability |
| 4 | KV v2 and leases | Versioned key/value storage, concurrency controls and lease lifecycle |
| 5 | Transit | Encryption, decryption, signing, verification, HMAC and key lifecycle services |
| 6 | High availability and recovery | Encrypted Raft, node identity, snapshots, backup/restore and failure recovery |
| 10 | Delivery ecosystem | CLI and deployment packages, public integrations, documentation and the approved UI scope |

Phases are sequential. A later phase does not begin until the active phase's Definition of Done is met and the owner accepts its phase report. The public roadmap omits edition-specific milestones that are not part of Community.

## Phase 1 — Seal and encrypted storage

**Approved design:** aws-lc-rs as the primary cryptographic provider; AES-256-GCM; random 96-bit nonces; a seal-root → keyring → versioned-DEK hierarchy; the KeyManagementProvider wrap/unwrap contract; Shamir default 5 shares / threshold 3; AWS KMS as the first auto-unseal provider; and redb as the initial backend. Community reserves tenant_id = root and does not claim cryptographic tenant isolation.

### 1.1 Cryptographic provider and test vectors

Use aws-lc-rs as primary provider and RustCrypto only for missing primitives. Add KAT and applicable Wycheproof vectors, including negative tests. Add deterministic boundary/property checks and coverage-guided fuzz targets in the same subphase as the cryptographic primitive; do not defer fuzzing to a later phase.

**Definition of Done:** provider integration and version are documented; KAT/Wycheproof, boundary, byte-mutation, truncation and wrong-key/context tests pass; fuzz targets cover generated round trips, arbitrary envelopes and authentication-field mutations; PR CI runs a bounded smoke campaign and scheduled CI runs extended campaigns. Record any technique not applicable to the component, with its rationale. Library choice alone is not a FIPS validation.

**Implementation status — complete:** [PR #10](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/10) integrates the AWS-LC provider, NIST KAT and Wycheproof fixtures. [PR #12](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/12) adds deterministic boundary/tamper coverage, three coverage-guided libFuzzer targets, pinned fuzz tooling, 60-second PR/push smoke campaigns and a weekly/manual five-minute campaign. CI run [#43523298611](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43523298611) passed on the exact PR head: Rust provider matrix (Linux x86_64, Linux aarch64, macOS, Windows), Rust 1.98 MSRV, all three fuzz targets and public quality gates. Gitleaks run [#43523298625](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43523298625) passed over all fetched Git history and refs. The fuzz smoke jobs completed 60 seconds each, with approximately 3.31 million, 9.82 million and 4.79 million executions respectively; these are run-specific observations, not coverage guarantees.

Provider implementation and boundaries are documented in [the crypto crate](crates/crypto/README.md), [provider selection and evidence](docs/security/crypto-provider-selection.md), [the fuzzing guide](fuzz/README.md), and [third-party notices](THIRD_PARTY_NOTICES.md). Fuzzing is part of Phase 1.1 and remains mandatory in later subphases wherever untrusted input, parsing, cryptographic envelopes or security-sensitive state is introduced. This does not complete the storage barrier, key-management contract, nonce-use budget, rotation, seal lifecycle or any other Phase 1 subphase.

### 1.2 Key-management provider contract

Implement the approved wrap(key_id, plaintext, context) and unwrap(wrapped, context) interface with typed errors, stable authenticated context, a versioned canonical envelope and an object-safe async provider boundary. The Community context binds tenant id root, key purpose and caller-supplied canonical scope. The FVK1 decoder rejects malformed metadata, unsupported versions, truncation and trailing bytes. Providers cryptographically bind key id, key version, algorithm and context to the protected ciphertext.

**Definition of Done:** contract tests cover correct/wrong context, per-byte context mutations, key identifier/version, unsupported algorithm and provider failures; deterministic property checks exercise canonical encode/decode invariants; coverage-guided fuzz tests exercise malformed wrapped-key envelopes and context mutations. PR CI runs bounded smoke campaigns and scheduled/manual CI runs extended campaigns. Cloud KMS adapters, key hierarchy orchestration, rotation and seal lifecycle remain outside this subphase.

**Implementation status — under review:** the interface, FVC1 context encoding, FVK1 envelope codec, test-only authenticated reference provider, deterministic property sweeps, Miri coverage for the pure-Rust parser and two additional fuzz targets are included in this change. See [the KMP contract and security notes](docs/security/key-management-provider-contract.md). Completion depends on exact PR-head quality gates, cross-platform tests, MSRV, fuzz smoke jobs and Gitleaks checks passing.

### 1.3 Recovery ceremony and Shamir

Implement the offline root ceremony, m-of-n custody and Shamir with configurable 5/3 defaults. The service never stores shares.

**Definition of Done:** ceremony and recovery procedures are documented and tested; recovery material never appears in logs, fixtures or service storage; property and fuzz tests validate share encoding, malformed inputs, reconstruction invariants and threshold boundaries.

### 1.4 Seal, unseal, bootstrap and generate-root

Implement the seal state machine, one-time bootstrap token and quorum-protected generate-root workflow.

**Definition of Done:** transition, replay, expiry, abuse and recovery tests pass; property/fuzz tests exercise invalid state transitions and malformed requests. The exact generate-root quorum remains pending and must be decided before implementing that parameter.

### 1.5 Auto-unseal

Define the provider trait and implement AWS KMS as the first provider. Document outage, authentication, fallback and recovery behavior.

**Definition of Done:** provider integration and failure-mode tests pass; credentials and provider context are not leaked; fuzz/property tests cover provider responses and error/timeout-state mapping where applicable.

### 1.6 Barrier encryption, AAD, nonce and rotation

Implement AES-256-GCM with the exact fixed-order, length-prefixed AAD fields in ADR-0004. New writes use the active key version; reads select by stored version; background re-encryption is resumable and auditable.

**Definition of Done:** tamper, wrong-path, wrong-version, AAD, nonce, rollover, interruption and old-key-retention tests pass; fuzz/property tests cover the serialized envelope, AAD encoder, nonce ledger and rotation-state transitions. The exact numeric rotation threshold and nonce-reservation block size remain pending; do not infer them.

### 1.7 Backend contract and initial redb backend

Implement get, put, delete, paginated list(prefix, limit, cursor), atomic txn with preconditions, and CAS by expected version or absence. Protected plaintext must be encrypted before reaching storage.

**Definition of Done:** the shared contract suite passes against redb, including linearizability, atomicity, concurrency, crash and recovery tests; property/fuzz tests cover cursors, prefixes, transaction batches, malformed records and serialized storage envelopes.

## Phase gates and evidence

Before implementing a subphase, record the concrete interfaces, dependencies, threat impact, tests and any unresolved owner decision relevant to that subphase. Starting with Phase 1.1, fuzzing is part of the implementation baseline: each subphase must add coverage-guided targets alongside the component it protects whenever untrusted bytes, external formats, parsers, protocol messages, cryptographic envelopes or security-sensitive state transitions are introduced. Every discovered defect must become a deterministic regression test. Run bounded fuzz smoke tests in PR CI and longer scheduled campaigns; keep curated seeds and retain crash artifacts. Add property testing (proptest), failure injection, concurrency testing (Loom where appropriate), interoperability, KAT/Wycheproof, Miri and benchmarks wherever applicable; document justified exclusions. Do not change approved decisions without a superseding owner-approved ADR. Each phase ends with updated ADRs, threat-model impact, security checklist, test evidence, known risks, rollback/recovery notes and owner acceptance.

Passing repository CI is not proof of runtime correctness, independent peer review, FIPS validation or an external security audit. Production use is not authorized by documentation or passing CI alone.

## Public edition boundary

Community must build and operate without the private Enterprise repository. Public interfaces are versioned and tested. Community is single-tenant with the logical tenant root; the reserved tenant field is a forward-compatibility measure, not multi-tenant behavior. See [ADR-0008](docs/adr/0008-community-enterprise-boundary.md) and [ADR-0019](docs/adr/0019-community-tenant-model.md).
