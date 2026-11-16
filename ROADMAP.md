# Ferrum Community roadmap

This roadmap describes the public Community edition. It records approved design direction and phase gates, not delivery dates or guarantees. Enterprise-only capabilities and private implementation plans are deliberately excluded.

## Current status

**Phase 0 — Foundations: documentation baseline in progress.** The repository now includes the initial cryptographic Cargo workspace, but it does not yet contain a complete Rust runtime, server or CLI. The public architecture decisions have been carried over into [Community ADRs](docs/adr/README.md). Phase 0 remains open until its remaining Definition of Done and owner acceptance are recorded.

**Phase 1 — Seal and encrypted storage: implementation in progress.** Subphase 1.1 (cryptographic provider, vectors, deterministic boundary tests and fuzz baseline) is implemented in [PR #10](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/10), [PR #12](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/12) and [PR #13](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/13). Subphase 1.2 (key-management provider contract) was implemented and merged by [PR #14](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/14), merge commit `7ef31c26fd7df300295f3b3c87a443ae02ba897a`. Subphase 1.3 (offline Shamir recovery primitives and ceremony runbook) was implemented and merged by [PR #15](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/15), commit `94377214fdc6204aaeb35237126139782ce38a35`. Subphase 1.4 has an initial process-local implementation under [PR #17](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/17); its owner-approved 2-of-3 root-operation quorum is implemented for `generate-root`, root rotation and root revocation; derived-credential revocation requires an audit event but no root quorum. Subphase 1.5 (provider-neutral Unsealer, mandatory Shamir 2-of-3 adapter and optional disabled-by-default AWS KMS adapter) was merged through [PR #18](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/18), merge commit `6a6f8a816565c714b5bce20f743421af83d4363a`. Exact-head CI [#43555804954](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43555804954) passed 19/19 jobs and Gitleaks [#43555804949](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43555804949) passed across fetched history and refs. Subphase 1.6 (canonical AAD, FBE1 envelope, key-versioned AES-GCM writes/reads, explicit nonce-budget contracts and resumable audited re-encryption) is implemented and exact-head validated in [PR #19](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/19), commit `dc6f3fcf7157a1468737e36ffe3a50862cae3db2`. CI [#43777573393](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43777573393) passed 21/21 jobs, including all 13 fuzz smoke targets, four-platform Rust checks, MSRV, Miri and public quality gates; Gitleaks [#43777573381](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43777573381) passed over fetched history and refs. Subphase 1.7 (durable redb backend) is implemented and owner-accepted in [PR #20](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/20). The implementation includes versioned CRUD/CAS, atomic conditional batches, prefix pagination, immediate-durability multi-writer transactions, persistent nonce reservations, atomic rotation checkpoint/audit operations, durable key-dependency inventory and retirement fences. Acceptance evidence includes the shared storage contract and regression/property tests, cross-handle/process concurrency, reopen and transaction-rollback recovery coverage, storage-decoder fuzzing, and exact-head CI/Gitleaks. CI run [#43789054115](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43789054115) passed all 23 jobs; Secret history scan [#43789054163](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43789054163) passed. The PR documents non-goals and residual boundaries accurately: no destructive power-loss certification across every filesystem, production backup/restore acceptance, FIPS validation or independent security audit is claimed. ADR-0004's numeric AES-GCM rotation threshold/safety margin and nonce-reservation block size remain owner-pending and are not guessed. The ADR-0004 numeric rotation threshold/safety margin and nonce-reservation block size remain owner-pending and have not been guessed. The approved design inputs are in public ADRs 0001–0004 and 0013–0014. The implementation must follow the phase gates below and must not guess explicitly pending parameters.

## Phase overview

| Phase | Name | Community outcome |
|---|---|---|
| 0 | Foundations | Public architecture, threat boundaries, decision records, workspace plan, governance and CI baseline |
| 1 | Seal and encrypted storage | Cryptographic boundary, seal lifecycle, key hierarchy, barrier encryption, recovery and encrypted persistence |
| 2 | [Native API, authentication, authorization and audit](#phase-2--native-api-authentication-authorization-and-audit) | Versioned `/v1` service, ordered TLS request pipeline, authentication, deny-by-default ACL and durable fail-closed audit |
| 3 | PKI engine | Certificate authority workflows, issuance, revocation and interoperability |
| 4 | KV v2 and leases | Versioned key/value storage, concurrency controls and lease lifecycle |
| 5 | Transit | Encryption, decryption, signing, verification, HMAC and key lifecycle services |
| 6 | High availability and recovery | Encrypted Raft, node identity, snapshots, backup/restore and failure recovery |
| 10 | Delivery ecosystem | CLI and deployment packages, public integrations, documentation and the approved UI scope |

Phases are sequential. A later phase does not begin until the active phase's Definition of Done is met and the owner accepts its phase report. The public roadmap omits edition-specific milestones that are not part of Community.

## Phase 1 — Seal and encrypted storage

**Approved design:** aws-lc-rs as the primary cryptographic provider; AES-256-GCM; random 96-bit nonces; a seal-root → keyring → versioned-DEK hierarchy; the KeyManagementProvider wrap/unwrap contract; the generic offline Shamir recovery utility default of 5 shares / threshold 3; a mandatory Shamir 2-of-3 adapter for the seal lifecycle; and optional provider adapters behind explicit selection; and redb as the initial backend. Community reserves tenant_id = root and does not claim cryptographic tenant isolation.

### 1.1 Cryptographic provider and test vectors

Use aws-lc-rs as primary provider and RustCrypto only for missing primitives. Add KAT and applicable Wycheproof vectors, including negative tests. Add deterministic boundary/property checks and coverage-guided fuzz targets in the same subphase as the cryptographic primitive; do not defer fuzzing to a later phase.

**Definition of Done:** provider integration and version are documented; KAT/Wycheproof, boundary, byte-mutation, truncation and wrong-key/context tests pass; fuzz targets cover generated round trips, arbitrary envelopes and authentication-field mutations; PR CI runs a bounded smoke campaign and scheduled CI runs extended campaigns. Record any technique not applicable to the component, with its rationale. Library choice alone is not a FIPS validation.

**Implementation status — complete:** [PR #10](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/10) integrates the AWS-LC provider, NIST KAT and Wycheproof fixtures. [PR #12](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/12) adds deterministic boundary/tamper coverage, three coverage-guided libFuzzer targets, pinned fuzz tooling, 60-second PR/push smoke campaigns and a weekly/manual five-minute campaign. CI run [#43523298611](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43523298611) passed on the exact PR head: Rust provider matrix (Linux x86_64, Linux aarch64, macOS, Windows), Rust 1.98 MSRV, all three fuzz targets and public quality gates. Gitleaks run [#43523298625](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43523298625) passed over all fetched Git history and refs. The fuzz smoke jobs completed 60 seconds each, with approximately 3.31 million, 9.82 million and 4.79 million executions respectively; these are run-specific observations, not coverage guarantees.

Provider implementation and boundaries are documented in [the crypto crate](crates/crypto/README.md), [provider selection and evidence](docs/security/crypto-provider-selection.md), [the fuzzing guide](fuzz/README.md), and [third-party notices](THIRD_PARTY_NOTICES.md). Fuzzing is part of Phase 1.1 and remains mandatory in later subphases wherever untrusted input, parsing, cryptographic envelopes or security-sensitive state is introduced. This does not complete the storage barrier, key-management contract, nonce-use budget, rotation, seal lifecycle or any other Phase 1 subphase.

### 1.2 Key-management provider contract

Implement the approved wrap(key_id, plaintext, context) and unwrap(wrapped, context) interface with typed errors, stable authenticated context, a versioned canonical envelope and an object-safe async provider boundary. The Community context binds tenant id root, key purpose and caller-supplied canonical scope. The FVK1 decoder rejects malformed metadata, unsupported versions, truncation and trailing bytes. Providers cryptographically bind key id, key version, algorithm and context to the protected ciphertext.

**Definition of Done:** contract tests cover correct/wrong context, per-byte context mutations, key identifier/version, unsupported algorithm and provider failures; deterministic property checks exercise canonical encode/decode invariants; coverage-guided fuzz tests exercise malformed wrapped-key envelopes and context mutations. PR CI runs bounded smoke campaigns and scheduled/manual CI runs extended campaigns. Cloud KMS adapters, key hierarchy orchestration, rotation and seal lifecycle remain outside this subphase.

**Implementation status — merged:** the interface, FVC1 context encoding, FVK1 envelope codec, test-only authenticated reference provider, deterministic property sweeps, Miri coverage for the pure-Rust parser and two additional fuzz targets were merged by [PR #14](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/14), commit `7ef31c26fd7df300295f3b3c87a443ae02ba897a`. Exact-head CI run [#43529291311](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43529291311) and Gitleaks run [#43529291268](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43529291268) passed. See [the KMP contract and security notes](docs/security/key-management-provider-contract.md). This contract does not itself provide a production KMS adapter, seal lifecycle or key hierarchy orchestration.

### 1.3 Recovery ceremony and Shamir

Implement the offline root ceremony, m-of-n custody and Shamir with configurable 5/3 defaults. The service never stores shares.

**Definition of Done:** ceremony and recovery procedures are documented and tested; recovery material never appears in logs, fixtures or service storage; property and fuzz tests validate share encoding, malformed inputs, reconstruction invariants and threshold boundaries.

**Implementation status — merged:** `ferrum-recovery` adds an offline-only Shamir workflow using pinned `vsss-rs` GF(256), the configurable 5/3 default policy, OS-seeded CSPRNG generation, strict FRS1 decoding, reconstruction integrity verification and zeroizing in-memory share buffers. The runbook defines custodian separation, offline handoff, verification, recovery and destruction. Two new fuzz targets cover arbitrary FRS1 data and share mutations; PR CI runs 60-second smoke tests and the scheduled/manual workflow is configured for five-minute campaigns. [PR #15](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/15) was merged as `94377214fdc6204aaeb35237126139782ce38a35`. Exact-head CI run [#43532940768](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43532940768) passed all quality, cross-platform, MSRV, Miri and fuzz checks; Gitleaks run [#43532940814](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43532940814) also passed. The main-branch post-merge CI is tracked separately. See [the recovery ceremony runbook](docs/security/recovery-ceremony.md) and [the recovery crate](crates/recovery/README.md). The FRS1 integrity tag detects reconstruction corruption; it is not a per-share signature or custodian attestation. This subphase supplies a Rust library and operational runbook, not a production ceremony CLI or externally audited recovery process.

### 1.4 Seal, unseal, bootstrap and generate-root

Implement the seal state machine, one-time bootstrap token and quorum-protected generate-root workflow.

**Definition of Done:** transition, replay, expiry, abuse and recovery tests pass; property/fuzz tests exercise invalid state transitions and malformed requests. The owner-approved root-operation quorum is 2-of-3 for generate-root, root rotation and root revocation. Missing/invalid configuration fails closed; derived-credential revocation requires audit but no root quorum.

**Implementation status — partial; implementation and exact-head CI validated:** [PR #17](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/17) adds `ferrum-seal` with a process-local Uninitialized/Sealed/Unsealed state machine, one-time expiring bootstrap token, FRS1 ceremony binding, Shamir-backed unseal, zeroizing in-memory root lifecycle and an explicitly configured 2-of-3 authorization gate for `generate-root`, root rotation and root revocation. It fails closed without valid explicit configuration; the generic 5/3 recovery default is not an implicit operation quorum. Derived-credential revocation is exposed through an audit-sink wrapper, requires no root fragments and records request/outcome fingerprints. The crate now has 20 tests, including one-fragment rejection, two-fragment success for all three root operations, missing/invalid config, duplicate/corrupt/cross-ceremony rejection and derived-credential audit behavior, plus deterministic root-length/subset sweeps. The nine fuzz targets include `seal_bootstrap_transitions` and `root_quorum_authorization`, both using synthetic runtime-only material. Exact-head CI run [#43542327701](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43542327701) passed all 16 jobs: four platform builds/tests (Linux x86_64, Linux aarch64, macOS, Windows), Rust 1.98 MSRV, Miri, all nine 60-second fuzz smoke campaigns and public repository quality gates. Gitleaks run [#43542327705](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43542327705) passed over fetched history and refs. This validates the PR code head `762bbe3fea4e6b8d572f8688df185e21005dd5dc`; subsequent documentation-only evidence updates require their own exact-head checks. The controller remains volatile, not restart-safe, durable or multi-process; Phase 1.7 must supply atomic persistence before service integration. This PR supplies a quorum authorization boundary and callback context, not a durable root mutation service, HTTP endpoint or production audit store. Recovery fragments must never be committed to the repository or exposed in logs/CI. Phase 1.5 AWS KMS, API-level throttling/audit persistence and production deployment remain outside this PR. The implementation does not claim proptest, Loom, measured coverage or service-level crash/restart tests for this controller.

### 1.5 Auto-unseal

The provider-neutral, object-safe async `Unsealer` port and mandatory Shamir 2-of-3 adapter remain the default. The generic offline recovery crate retains its separate 5-of-3 default. Alternative providers require explicit selection and never fall back silently.

The optional `aws-kms` feature is disabled by default. When explicitly enabled, `ferrum-seal` compiles the official AWS SDK for Rust (`aws-config` 1.13.2 and `aws-sdk-kms` 1.129.0) and Tokio only for that feature; the default/core graph remains cloud-independent. `AwsKmsUnsealer::<AwsSdkKmsApi>::from_environment` resolves the SDK standard credential chain (environment, shared profile/config, web identity and workload/instance role providers) without hardcoded credentials, derives and pins the Region from a full KMS key ARN, then calls `DescribeKey`. It fails closed unless the exact ARN refers to an enabled customer-managed `SYMMETRIC_DEFAULT` key with `ENCRYPT_DECRYPT` usage.

The SDK adapter performs KMS `Encrypt` and `Decrypt` with the same SHA-256 fingerprint of canonical FVC1 context containing tenant=root, purpose=seal-root and public ceremony id. The plaintext context never includes root material, shares or bootstrap tokens. The repository includes least-privilege runtime IAM/key-policy examples, a separate audit-role policy and `scripts/aws-kms-live-verify.sh` for a controlled synthetic SDK round-trip, IAM simulation and matching regional CloudTrail Event History events. CI compiles the feature and live example using fake-only tests; it never receives AWS credentials.

**Security boundary:** a principal with `kms:Decrypt` and access to the wrapped root can unseal without presenting Shamir shares. This is a high-impact alternate trust path and must be narrowly scoped and audited. It does not satisfy or bypass the independent explicit 2-of-3 root-operation quorum for `generate-root`, root rotation or root revocation. Missing/invalid quorum configuration remains fail-closed. See [ADR-0024](docs/adr/0024-unsealer-port-and-optional-aws-kms.md) and [auto-unseal security notes](docs/security/auto-unseal.md).

**Verification boundary:** the real account test against AWS and CloudTrail has not been run by this repository change; an authorized operator must run the script using the intended runtime and audit identities and record sanitized event IDs, role ARN, key ARN, Region and timestamp. No credential values or production root material may be committed or pasted into chat. Durable wrapped-root persistence, restart safety, service integration and production readiness remain Phase 1.7 or later scope.

### 1.6 Barrier encryption, AAD, nonce and rotation

Implement AES-256-GCM through the approved AWS-LC provider with the exact fixed-order, length-prefixed AAD fields in ADR-0004. FBE1 carries the format version, key id/version, random 96-bit nonce and ciphertext with the full 128-bit tag. New writes use the active DEK version; reads select the recorded version. The AAD v1 encoder binds tenant root, u16-BE format version, u64-BE key version and already-canonical path bytes, each with a u32-BE length prefix.

The nonce-use ledger must atomically persist a per-key-version high-water reservation before encryption. A possibly partially consumed reservation is spent after failure/restart. The rotation worker performs bounded stable-page reads, authenticated decrypt/re-encrypt, CAS updates with matching audit events, and durable checkpoints with audit. Old DEKs cannot be retired until an inventory proves no live records, backups, snapshots or in-progress jobs depend on them.

**Definition of Done:** tamper, wrong-path, wrong-version, AAD, nonce, rollover, interruption, CAS-conflict retry/replay and old-key-retention tests pass; proptest and fuzz cover the FBE1 parser, AAD encoder, nonce reservation state and rotation checkpoints. CI runs bounded fuzz smoke campaigns; scheduled CI runs extended campaigns. A persistent backend must prove reservations/checkpoints/CAS/audit atomicity and restart safety.

**Explicitly pending owner parameters:** exact numeric AES-GCM rotation threshold and quantitative safety margin; exact nonce-reservation block size. The API has no defaults and requires explicit values. The hard less-than-2^32 ceiling is only an upper bound, not a selected operational threshold. Do not infer either value.

**Implementation status — implemented and CI-validated:** PR #19 adds `crates/crypto/src/barrier.rs`, the FBE1 parser, ADR-0004 AAD encoder, explicit per-key-version nonce reservation contract, key dependency retirement gate, and bounded re-encryption worker with checkpoint/CAS/audit contracts. It also adds regression coverage for corrupt active-version records and CAS-conflict replay, proptest, three dedicated libFuzzer targets, AAD benchmarks and Miri coverage. Exact-head CI [#43777573393](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43777573393) passed 21/21 jobs and Gitleaks [#43777573381](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43777573381) passed. The concrete durable redb adapters, persistent atomicity/linearizability, crash/restart recovery and service integration are Phase 1.7; this subphase does not claim production durability. The two numeric ADR-0004 parameters remain pending owner approval.

### 1.7 Backend contract and initial redb backend

Implement get, put, delete, paginated list(prefix, limit, cursor), atomic txn with preconditions, and CAS by expected version or absence. Protected plaintext must be encrypted before reaching storage.

**Definition of Done:** the shared contract suite passes against redb, including linearizability, atomicity, concurrency, crash and recovery tests; property/fuzz tests cover cursors, prefixes, transaction batches, malformed records and serialized storage envelopes.

**Subphase 1.7 — durable redb backend: implementation complete and owner-accepted in PR #20.** `ferrum-storage` implements versioned CRUD/CAS, conditional atomic batches, prefix pagination, immediate-durability multi-writer redb transactions, the Phase 1.6 persistent nonce ledger, atomic rotation CAS/checkpoint/audit transactions, and a durable key-dependency index with retirement fences. Storage fuzzing covers cursor, record, nonce-state and rotation-checkpoint decoders. Regression/property tests cover reopen persistence, cross-handle/process concurrency, non-overlapping nonce reservations, failed preconditions, uncommitted transaction rollback, monotonic CAS versions across delete/recreate, inventory reconciliation and dependency-retirement races. Exact-head CI and Secret history scan passed; see the validation evidence in the Phase 1 status above. Known limits remain explicit: no destructive power-loss certification across all filesystems, production backup/restore acceptance, FIPS validation or independent security audit is claimed. The ADR-0004 nonce block size and AES-GCM rotation threshold remain owner-pending explicit caller inputs, with no guessed defaults.

## Phase 2 — Native API, authentication, authorization and audit

**Status — planned; formal scope and phase gates documented. No Phase 2 implementation is claimed by this roadmap entry.** This phase turns the Community libraries into a native, versioned service boundary. It implements the request pipeline and security controls already required by [ADR-0005](docs/adr/0005-request-pipeline-and-fail-closed-audit.md), uses the extension rules in [ADR-0002](docs/adr/0002-async-extension-contracts.md), and follows the native API lifecycle in [ADR-0015](docs/adr/0015-reproducible-builds-and-api-versioning.md).

### 2.1 Objective and scope

Deliver an operable Community server with a native `/v1` API, TLS 1.3 transport using rustls, a consistent request lifecycle, authentication, identity-based rate limiting, canonical route and ACL evaluation, and durable audit around sensitive operations. The pipeline must follow the owner-approved ADR-0005 order:

1. TLS 1.3 listener using rustls.
2. HTTP/gRPC server and server-generated request ID.
3. Request-size and time limits.
4. IP-based pre-authentication rate limit.
5. Local seal-state check.
6. Authentication.
7. Identity-based rate limit.
8. Canonical route and ACL evaluation.
9. Handler.
10. Durable audit before and after sensitive operations.

The phase also establishes the approved API contract, error behavior, server configuration and integration evidence needed to use that pipeline safely.

**Community boundary:** Community remains single-tenant with the logical tenant identifier `root`; the server must derive this value from authenticated and authorized context and must not accept a freely client-selected tenant. This does not provide cryptographic tenant isolation or introduce multi-tenancy; see [ADR-0019](docs/adr/0019-community-tenant-model.md).

**Explicitly out of scope:** implementing the PKI engine (Phase 3), KV v2 and leases (Phase 4), Transit (Phase 5), encrypted Raft/HA (Phase 6), or the CLI, UI and deployment ecosystem (Phase 10). The optional Vault-API compatibility subset in [ADR-0018](docs/adr/0018-vault-api-compatibility-subset.md) is not the native API and must not be pulled into this phase; it is considered only after the native API is stable and its legal-review condition is satisfied. Phase 2 must not add Community dependencies on the private Enterprise edition.

### 2.2 Entry gates and dependencies

The roadmap's phase-sequencing rule remains in force: Phase 2 implementation does not begin until the preceding phase gates have been met and the owner has accepted their reports.

- **Phase 0:** foundations, public workspace/documentation baseline, repository governance and applicable CI Definition of Done must be completed and owner-accepted.
- **Phase 1:** all Phase 1 subphases must be accepted. In particular, the current Phase 1.4 status is still recorded as partial: the process-local seal lifecycle must be integrated with the accepted durable storage boundary before a service can claim restart-safe seal state. The Phase 1.6 ADR-0004 numeric parameters remain explicitly pending; they must be approved or otherwise resolved through an owner-authorized ADR before a service path that depends on them is enabled. Do not assign defaults or silently bypass these conditions.
- **Storage and crypto foundations:** the accepted Phase 1.6/1.7 contracts are dependencies for protected state, durable audit coordination and persistence; this does not mean the Phase 2 server itself may store protected plaintext in generic KV.
- **Design gate 2.0:** the Phase 2 decisions listed below must be approved before their dependent implementation subphases begin.
- **Edition boundary:** the service must build and operate without Enterprise code, credentials, private packages or services.

Subphase dependencies are sequential where security decisions require it: 2.0 precedes all implementation; 2.1 precedes transport integration; 2.2 establishes the request context and ordered pipeline used by 2.3–2.5; authentication (2.3) precedes identity-based authorization (2.4); the audit contract (2.5) must be integrated before sensitive handlers are enabled; 2.6 validates the complete vertical path. Work may proceed in parallel only where these contracts are already approved and no dependency is bypassed.

### 2.3 Subphases and their Definition of Done

#### 2.0 — Owner decisions and API/security contract baseline

**Scope:** resolve the owner-pending choices in §2.5; inventory the native endpoints and operations that Phase 2 will expose; classify each route by seal availability, authentication, authorization and audit requirements; record the resulting public interfaces and threat-model impact in ADRs. This is a design and approval gate, not permission to invent implementation defaults.

**Definition of Done:**
- The native endpoint/operation catalog is reviewed and owner-approved, including explicit non-goals and deferred operations.
- Transport, wire/schema format, credential model, identity lifecycle, ACL semantics, rate-limit policy, request limits, sealed-mode allowlist and audit details have decisions or explicit documented exclusions.
- Every decision that changes an approved architecture requirement is recorded in a new or superseding owner-approved ADR; pending decisions remain visibly pending.
- The request pipeline and its security invariants are mapped to tests and responsible subphases.
- No implementation subphase relies on an unapproved credential format, authorization rule, numerical limit or audit durability assumption.

#### 2.1 — Native `/v1` API and contract definitions

**Scope:** define the native API route catalog, request/response schemas, error model, versioning behavior and compatibility rules. ADR-0015 already approves `/v1`, semantic versioning and a two-minor-version deprecation policy; this subphase must apply those decisions rather than redefine them. The exact endpoint list and wire format remain subject to 2.0.

**Definition of Done:**
- Every Phase 2 endpoint has a documented method, canonical route, input/output schema, error behavior and security classification.
- Each endpoint identifies whether it is available while sealed, which authentication and ACL checks apply, and which audit events are mandatory.
- The API schema/source of truth and contract-test approach are selected by an owner-approved decision; no schema technology is assumed here.
- Versioning and deprecation rules are covered by automated contract tests.
- Unsupported and deferred endpoints are documented; future Phase 3–6 engines and the optional Vault compatibility surface are not represented as implemented.

#### 2.2 — TLS server and ordered request pipeline

**Scope:** provide the server listener and approved HTTP/gRPC transport, TLS 1.3 via rustls, request IDs, bounded request size/time, IP-based pre-authentication rate limiting, seal-state gating and the explicitly approved minimal allowlist for non-sensitive sealed-mode endpoints. Preserve ADR-0005's order; middleware must not reorder or bypass security gates.

**Definition of Done:**
- The selected transport starts with TLS 1.3 and rejects invalid/untrusted transport configuration according to the approved configuration contract.
- Each request receives a server-generated request ID and bounded resource/deadline context.
- The order of all pipeline stages is verified by integration tests, including early rejection paths.
- IP-based pre-authentication rate limiting uses only the owner-approved client-address/trusted-proxy rules; spoofable client headers are not trusted by default.
- Sealed-mode behavior is deny-by-default except for the explicit approved allowlist.
- Cancellation, timeout and connection termination leave state and resources consistent; applicable concurrency/failure tests are included.

#### 2.3 — Authentication and identity lifecycle

**Scope:** implement the owner-approved authentication method(s), establish a trusted server-side identity context, and apply identity-based rate limiting after authentication. Pluggable authentication methods that require dynamic dispatch follow ADR-0002: async traits with `Send + Sync`; each extension documents errors, cancellation, lifetimes, concurrency and security guarantees.

**Definition of Done:**
- The approved credential validation and identity lifecycle contract is implemented, including the approved issuance/bootstrap, expiry, renewal, revocation and invalidation behavior where applicable.
- Unauthenticated, malformed, expired, revoked, replayed and otherwise invalid credentials fail closed and do not reach protected handlers.
- Identity is produced by the authentication boundary; client-supplied identity or tenant fields cannot override it.
- Identity-based rate limiting is enforced after successful authentication.
- Secret credentials and tokens are not written to logs, audit payloads, error bodies, test artifacts or fuzz corpora.
- Provider contract tests prove the required async/dynamic compatibility and cancellation behavior.

#### 2.4 — Canonical routing and deny-by-default authorization

**Scope:** evaluate an authenticated identity against the canonical route/action/resource and the owner-approved ACL model. Community's logical tenant remains `root`; mounts and ACL provide the approved Community boundary. No client-controlled tenant selector or implicit allow rule is introduced.

**Definition of Done:**
- Every protected route is covered by an explicit policy decision; missing, malformed, unavailable or indeterminate policy state denies access.
- Route canonicalization occurs before policy evaluation and is consistent between routing, authorization and audit.
- Tests cover path aliases, encoding/normalization edge cases, method/action confusion, policy absence, conflicting rules and attempted privilege escalation according to the approved policy semantics.
- The authenticated identity and `root` tenant context are derived server-side.
- Authorization decisions are explainable through non-secret diagnostics/audit references without disclosing credentials or protected values.

#### 2.5 — Durable audit and fail-closed operation boundary

**Scope:** implement ADR-0005 audit requirements. Minimum destinations are a JSON file with hash-chain integrity and stdout/syslog; retention is configurable with the approved 90-day default. Sensitive operations require durable audit intent before execution and a durable outcome afterward. If the required intent cannot be persisted, the operation is not executed; for reads, protected data is not disclosed first. If configured sinks fail, the operation is blocked. When audit and business state do not share a transaction, use an approved outbox, idempotency and reconciliation design.

**Definition of Done:**
- Audit event schema, canonical serialization, hash-chain construction/verification, append/concurrency behavior, sink configuration and retention enforcement match owner-approved decisions.
- Required intent is durably recorded before a sensitive mutation or secret disclosure; outcome is durably recorded afterward.
- Sink failure, partial write, process interruption, retry and recovery tests prove fail-closed behavior and do not silently lose or duplicate security-relevant outcomes.
- When a single transaction cannot cover audit and state, the approved outbox/idempotency/reconciliation contract is implemented and tested.
- Chain verification detects tampering, truncation or reordering within the documented threat boundary. A local hash chain is not described as immutable off-host storage against an attacker controlling the host.
- Audit payloads avoid plaintext secrets, credentials, recovery shares and sensitive request bodies.

#### 2.6 — End-to-end service integration and security acceptance

**Scope:** wire the approved route catalog through the actual server, request pipeline, authentication, ACL, handlers and durable audit. Add operational configuration and runbooks needed to run, diagnose and safely stop the Community service. Only endpoints explicitly approved in 2.0 and implemented in this phase may be enabled.

**Definition of Done:**
- A clean environment can build and start the Community service using documented, validated configuration without Enterprise access or production credentials in CI.
- End-to-end tests traverse the actual TLS listener and verify sealed/unsealed behavior, authentication, identity rate limits, allow/deny policy decisions, handler execution and audit outcomes.
- Negative E2E tests prove that authentication, authorization, rate-limit and audit failures prevent protected operations and secret disclosure.
- Restart, cancellation, timeout and failure-injection scenarios preserve the documented durable state and audit guarantees.
- Security review findings from the phase's threat-model update are resolved or explicitly accepted by the owner with remediation tracking.
- Operational documentation describes configuration, key/certificate inputs, sealed-mode behavior, audit verification, failure diagnosis and recovery boundaries.
- All required CI and evidence gates in §2.6 and ADR-0010 pass on the exact PR head.

### 2.4 Interface and contract inventory

The following are required contract boundaries. These descriptions identify responsibilities, not final Rust type names, method signatures, wire formats or crate boundaries; those details are selected in 2.0 and recorded in the relevant ADRs.

| Boundary | Required contract |
|---|---|
| Listener and transport | TLS 1.3/rustls termination, approved HTTP/gRPC protocol(s), request lifecycle, connection failure and cancellation behavior |
| Request context | Server-generated request ID, trusted peer/client-address context, deadline and size bounds, seal state, authenticated principal when available, canonical route/action and Community tenant `root` |
| API handler | Versioned request/response contract, typed error behavior, no bypass around pipeline controls |
| Authentication extension | Credential validation, trusted identity production, typed failure behavior, cancellation and concurrency guarantees; dynamic plugins follow ADR-0002 |
| Rate limiting | Separate pre-auth IP and post-auth identity boundaries, with source-of-client-address and shared/process scope explicitly decided |
| Authorization | Canonical resource/action + trusted identity → explicit allow/deny; unavailable or indeterminate state denies |
| Audit sink | Durable intent/outcome append and verification contract, sink failure semantics, cancellation behavior, and no secret disclosure |
| Configuration | Validated startup configuration; unsafe or incomplete required security configuration fails closed; defaults exist only where approved |

### 2.5 Decisions that still require explicit owner approval

The ADRs define required behavior but do not settle every implementation choice. The following must not be guessed:

1. **Transport and server implementation:** whether Community exposes HTTP, gRPC or both in this phase; the concrete server framework; protocol mapping and any schema-generation technology.
2. **Native API catalog:** exact resources, routes, methods and operations included in the Phase 2 MVP; request/response representation, pagination and error envelope details.
3. **Authentication model:** supported authentication method(s), principal/identity fields, credential representation and storage, issuance/bootstrap authority, token/session lifetime, renewal, revocation, rotation and replay behavior. Do not assume AppRole or Vault token compatibility; ADR-0018 is a later optional compatibility surface.
4. **Authorization model:** ACL policy syntax and storage, resource/path grammar, capability vocabulary, matching and precedence rules, policy update/version semantics, administrative bootstrap and recovery from policy lockout.
5. **Rate limiting and request bounds:** algorithms, windows, burst/quotas, per-source identity rules, persistence/distribution scope, trusted-proxy configuration, maximum request size, timeouts and failure behavior. ADR-0005 requires these controls but supplies no numeric limits.
6. **Sealed-mode allowlist:** exact endpoints and response fields permitted while sealed, with rationale that they are non-sensitive.
7. **TLS certificate operations:** certificate/key provisioning, trust roots, rotation and reload behavior. TLS 1.3 with rustls is approved; the lifecycle and deployment mechanism are not specified here.
8. **Audit details:** event schema and canonical encoding, hash algorithm and chain metadata, append durability boundary, sink selection/configuration, rotation/archival/export, retention enforcement and verification procedure. ADR-0005 approves JSON-file hash-chain plus stdout/syslog and a configurable 90-day default but does not define all these mechanics.
9. **Audit/state coordination:** transaction boundary and the outbox/idempotency/reconciliation mechanism to use when audit and protected state cannot commit atomically.
10. **Service configuration and operations:** configuration source/format, secret handling for server credentials, health/readiness semantics, graceful shutdown and supported deployment assumptions.

A decision may be deferred only if the dependent feature is disabled and the exclusion is explicit. Do not implement a permissive fallback to avoid an unresolved decision. Changes to owner-approved requirements need a new or superseding ADR.

### 2.6 Required test and evidence strategy

Apply [ADR-0010](docs/adr/0010-testing-and-security-evidence.md) to each subphase; do not defer fuzzing or negative security tests until the end.

- **Unit tests:** request parsing and validation, route canonicalization, pipeline ordering, rate-limit boundaries, credential lifecycle, identity construction, policy evaluation/deny-by-default, audit serialization/hash-chain verification and configuration validation.
- **Property tests (proptest):** canonical route invariants, policy decision invariants, credential/event codec round trips, audit-chain continuity, and rate-limit/state invariants where the implementation has deterministic properties.
- **Coverage-guided fuzzing (cargo-fuzz):** all untrusted parsers and decoders introduced by the chosen transport/schema, credential formats, route canonicalization, policy parser, audit record decoder and any security-sensitive state transition. Fuzz targets use synthetic material only; corpora must not contain valid credentials, secrets, recovery shares or production audit data. Add a deterministic regression test for every discovered defect.
- **Integration tests:** a real in-process TLS listener and the selected transport, request middleware, trusted-proxy boundary, storage/seal integration, authentication plugins, ACL decisions, rate limiter and audit sinks. Include process restart and injected sink/storage failure where persistence is involved.
- **Security tests:** unauthorized/unauthenticated requests, expired/revoked/replayed credentials, spoofed client-address headers, path and encoding ambiguity, policy bypass, privilege escalation, sealed-mode bypass, oversized/slow requests, cancellation, secret leakage and audit failure. Add protocol-specific negative cases after the transport is chosen.
- **End-to-end tests:** exercise the actual listener and every approved Phase 2 route across success and failure paths. Prove that no protected handler or secret response is reachable when any required earlier gate denies or when required audit intent cannot be persisted.
- **Concurrency and runtime tools:** use Loom where shared state/concurrency models make it appropriate, Miri for eligible pure-Rust code, failure injection for persistence and cancellation, and Criterion for performance-sensitive paths. Document justified exclusions rather than claiming unrun techniques.
- **Coverage and CI:** meet the ADR-0010 target of at least 90% measured coverage for the `auth`, `policy` and `audit` components, alongside the applicable existing crypto/seal targets. CI must enforce formatting, clippy with warnings denied, tests, dependency policy/audit, measured coverage and bounded fuzz smoke. Longer fuzz campaigns run on the scheduled/manual workflow. Run the applicable supported-platform and MSRV matrix.
- **Evidence hygiene:** retain exact-head CI links, coverage reports, fuzz artifacts, threat-model changes, security checklist, configuration/runbook evidence and a list of limitations. Never use real credentials or production secrets in CI fixtures or artifacts.

### 2.7 Phase 2 acceptance criteria

Phase 2 is complete only when all of the following are true and the owner accepts the phase report:

1. The Phase 2 entry gates are satisfied and every implementation-affecting owner decision is resolved in an ADR or explicitly excluded with its dependent feature disabled.
2. The documented native `/v1` API catalog and schemas match the running service; semantic versioning and the two-minor deprecation policy are enforced by contract tests.
3. The actual service enforces the full ADR-0005 pipeline in the approved order, using TLS 1.3/rustls and the approved transport(s).
4. Request limits, pre-auth IP rate limiting, sealed-mode gating, authentication, identity-based rate limiting and canonical ACL checks cannot be bypassed or silently skipped.
5. Authorization is deny-by-default; Community remains single-tenant with tenant `root` derived from trusted server context.
6. Required audit intent is durable before sensitive operations or secret disclosure, outcomes are durably recorded afterward, and sink failures block the operation. Audit chain verification, retention and recovery behavior are evidenced within the documented threat boundary.
7. Unit, property, fuzz, integration, security and end-to-end suites pass; every discovered defect has a regression test; coverage meets the ADR-0010 target for the new `auth`, `policy` and `audit` components.
8. Applicable CI, dependency/supply-chain checks, platform/MSRV checks and secret scanning pass on the exact final PR head. Evidence links point to that exact head.
9. Threat model, ADRs, roadmap, security checklist, API documentation, deployment/configuration instructions and operational/failure runbooks are updated and mutually consistent.
10. No Enterprise dependency, undocumented compatibility claim, implicit KMS fallback, multi-tenant claim, FIPS claim or independent-audit claim is introduced.
11. The owner accepts the phase report, including residual risks, deferred capabilities and explicit non-goals.

**Phase 2 does not make Ferrum a complete secrets-management product by itself.** PKI, KV v2, Transit, HA/recovery, Vault API compatibility, CLI, UI and release distribution remain in their separately defined roadmap phases. Passing Phase 2 CI is not production authorization, an external security audit or FIPS validation.

## Phase gates and evidence

Before implementing a subphase, record the concrete interfaces, dependencies, threat impact, tests and any unresolved owner decision relevant to that subphase. Starting with Phase 1.1, fuzzing is part of the implementation baseline: each subphase must add coverage-guided targets alongside the component it protects whenever untrusted bytes, external formats, parsers, protocol messages, cryptographic envelopes or security-sensitive state transitions are introduced. Every discovered defect must become a deterministic regression test. Run bounded fuzz smoke tests in PR CI and longer scheduled campaigns; keep curated seeds and retain crash artifacts. Add property testing (proptest), failure injection, concurrency testing (Loom where appropriate), interoperability, KAT/Wycheproof, Miri and benchmarks wherever applicable; document justified exclusions. Do not change approved decisions without a superseding owner-approved ADR. Each phase ends with updated ADRs, threat-model impact, security checklist, test evidence, known risks, rollback/recovery notes and owner acceptance.

Passing repository CI is not proof of runtime correctness, independent peer review, FIPS validation or an external security audit. Production use is not authorized by documentation or passing CI alone.

## Public edition boundary

Community must build and operate without the private Enterprise repository. Public interfaces are versioned and tested. Community is single-tenant with the logical tenant root; the reserved tenant field is a forward-compatibility measure, not multi-tenant behavior. See [ADR-0008](docs/adr/0008-community-enterprise-boundary.md) and [ADR-0019](docs/adr/0019-community-tenant-model.md).
