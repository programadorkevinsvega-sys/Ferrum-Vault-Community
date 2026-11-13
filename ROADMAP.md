# Ferrum Community roadmap

This roadmap describes the public Community edition. It records approved design direction and phase gates, not delivery dates or guarantees. Enterprise-only capabilities and private implementation plans are deliberately excluded.

## Current status

**Phase 0 — Foundations: documentation baseline in progress.** The repository is documentation-only: it has no Cargo workspace, Rust runtime, server or CLI. The public architecture decisions have been carried over into [Community ADRs](docs/adr/README.md). Phase 0 remains open until its remaining Definition of Done and owner acceptance are recorded.

**Phase 1 — Seal and encrypted storage: implementation in progress.** Subphase 1.1 (cryptographic provider and test vectors) is implemented and CI-verified in [PR #10](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/10). Subphases 1.2–1.7 remain pending. The approved design inputs are in public ADRs 0001–0004 and 0013–0014. The implementation must follow the phase gates below and must not guess explicitly pending parameters.

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

**Approved design:** aws-lc-rs as the primary cryptographic provider; AES-256-GCM; random 96-bit nonces; a seal-root → keyring → versioned-DEK hierarchy; the `KeyManagementProvider` wrap/unwrap contract; Shamir default 5 shares / threshold 3; AWS KMS as the first auto-unseal provider; and redb as the initial backend. Community reserves `tenant_id = root` and does not claim cryptographic tenant isolation.

### 1.1 Cryptographic provider and test vectors
Use aws-lc-rs as primary provider and RustCrypto only for missing primitives. Add KAT and applicable Wycheproof vectors, including negative tests.

**Definition of Done:** provider integration and version are documented; KAT/Wycheproof and invalid-tag/AAD tests pass. Library choice alone is not a FIPS validation.

**Implementation status — complete for subphase 1.1:** [PR #10](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/10) integrates the approved AWS-LC provider and records the fixture provenance. [post-merge CI run #43518675434](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43518675434) passed on 2026-11-13: Linux x86_64, Linux aarch64, macOS, Windows, Rust 1.98 MSRV, public quality gates and Gitleaks. The suite executes two AES-256-GCM KAT cases, all 66 Wycheproof vectors for the approved AES-256 / 96-bit IV / 128-bit tag profile (39 valid, 27 invalid), plus AAD/tag tamper tests.

Provider implementation and boundaries are documented in [the crypto crate](crates/crypto/README.md), [provider selection and evidence](docs/security/crypto-provider-selection.md), and [third-party notices](THIRD_PARTY_NOTICES.md). This closes 1.1 only; it does not complete the storage barrier, key-management contract, nonce-use budget, rotation, seal lifecycle or any other Phase 1 subphase.

### 1.2 Key-management provider contract
Implement the approved `wrap(key_id, plaintext, context)` and `unwrap(wrapped, context)` interface with typed errors and stable authenticated context.

**Definition of Done:** contract and compatibility tests cover correct context, wrong context, key identifier/version and provider failures.

### 1.3 Recovery ceremony and Shamir
Implement the offline root ceremony, m-of-n custody and Shamir with configurable 5/3 defaults. The service never stores shares.

**Definition of Done:** ceremony and recovery procedures are documented and tested; recovery material never appears in logs, fixtures or service storage.

### 1.4 Seal, unseal, bootstrap and generate-root
Implement the seal state machine, one-time bootstrap token and quorum-protected generate-root workflow.

**Definition of Done:** transition, replay, expiry, abuse and recovery tests pass. The exact generate-root quorum remains pending and must be decided before implementing that parameter.

### 1.5 Auto-unseal
Define the provider trait and implement AWS KMS as the first provider. Document outage, authentication, fallback and recovery behavior.

**Definition of Done:** provider integration and failure-mode tests pass; credentials and provider context are not leaked.

### 1.6 Barrier encryption, AAD, nonce and rotation
Implement AES-256-GCM with the exact fixed-order, length-prefixed AAD fields in ADR-0004. New writes use the active key version; reads select by stored version; background re-encryption is resumable and auditable.

**Definition of Done:** tamper, wrong-path, wrong-version, AAD, nonce, rollover, interruption and old-key-retention tests pass. The exact numeric rotation threshold and nonce-reservation block size remain pending; do not infer them.

### 1.7 Backend contract and initial redb backend
Implement `get`, `put`, `delete`, paginated `list(prefix, limit, cursor)`, atomic `txn` with preconditions, and CAS by expected version or absence. Protected plaintext must be encrypted before reaching storage.

**Definition of Done:** the shared contract suite passes against redb, including linearizability, atomicity, concurrency, crash and recovery tests.

## Phase gates and evidence

Before implementing a subphase, record the concrete interfaces, dependencies, threat impact, tests and any unresolved owner decision relevant to that subphase. Do not change approved decisions without a superseding owner-approved ADR. Each phase ends with updated ADRs, threat-model impact, security checklist, test evidence, known risks, rollback/recovery notes and owner acceptance.

Passing repository CI is not proof of runtime correctness, independent peer review, FIPS validation or an external security audit. Production use is not authorized by documentation or passing CI alone.

## Public edition boundary

Community must build and operate without the private Enterprise repository. Public interfaces are versioned and tested. Community is single-tenant with the logical tenant `root`; the reserved tenant field is a forward-compatibility measure, not multi-tenant behavior. See [ADR-0008](docs/adr/0008-community-enterprise-boundary.md) and [ADR-0019](docs/adr/0019-community-tenant-model.md).
