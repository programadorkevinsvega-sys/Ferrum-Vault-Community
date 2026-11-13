# Ferrum Community roadmap

This roadmap describes the public Community edition. It records approved design direction and phase gates, not delivery dates or guarantees. Enterprise-only capabilities and private implementation plans are deliberately excluded.

## Current status

**Phase 0 — Foundations: documentation baseline in progress.** The repository is documentation-only: it has no Cargo workspace, Rust runtime, server or CLI. The public architecture decisions have been carried over into [Community ADRs](docs/adr/README.md). Phase 0 remains open until its remaining Definition of Done and owner acceptance are recorded.

**Phase 1 — Seal and encrypted storage: implementation in progress.** Subphase 1.1 (cryptographic provider, vectors and fuzz baseline) is implemented in [PR #10](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/10); the additional fuzz and boundary hardening is under review in this PR. Subphases 1.2–1.7 remain pending. The approved design inputs are in public ADRs 0001–0004 and 0013–0014. The implementation must follow the phase gates below and must not guess explicitly pending parameters.

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

**Implementation status — previous baseline complete, fuzz extension under review:** [PR #10](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/10) integrates the AWS-LC provider, KAT and Wycheproof fixtures. This PR adds the missing fuzz baseline and expanded deterministic checks before considering Phase 1.1 complete under the strengthened acceptance criteria.

Provider implementation and boundaries are documented in [the crypto crate](crates/crypto/README.md), [provider selection and evidence](docs/security/crypto-provider-selection.md), [the fuzzing guide](fuzz/README.md), and [third-party notices](THIRD_PARTY_NOTICES.md). The fuzzing extension is part of Phase 1.1, not a later enhancement; it does not complete the storage barrier, key-management contract, nonce-use budget, rotation, seal lifecycle or any other Phase 1 subphase.

### 1.2 Key-management provider contract

Implement the approved wrap(key_id, plaintext, context) and unwrap(wrapped, context) interface with typed errors and stable authenticated context.

**Definition of Done:** contract and compatibility tests cover correct context, wrong context, key identifier/version and provider failures; property and fuzz tests exercise malformed wrapped-key envelopes and context mutations.

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
