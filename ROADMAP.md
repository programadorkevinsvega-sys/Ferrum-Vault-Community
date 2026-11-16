# Ferrum Community roadmap

This roadmap describes the public Community edition. It records approved design direction and phase gates, not delivery dates or guarantees. Enterprise-only capabilities and private implementation plans are deliberately excluded.

## Current status

**Phase 0 — Foundations: complete and owner-accepted on 2026-11-16.** The Community public baseline is in place: migration/provenance records, the public ADR carryover and source classification, edition-separation rules, the Rust workspace and pinned toolchain, contribution/security/license policies, CI and secret-history scanning, and an active `main` ruleset. The owner explicitly accepted the Phase 0 closeout on 2026-11-16. Legal/trademark clearance, private vulnerability intake configuration and external-contributor terms remain separately identified pre-launch or external-contribution gates; they are not represented as completed.

**Phase 1 — Seal and encrypted storage: complete, integrated into `main`, and owner-accepted.** All Phase 1.1–1.7 implementation, test and documentation PRs are merged into `main`: [#10](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/10), [#11](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/11), [#12](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/12), [#13](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/13), [#14](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/14), [#15](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/15), [#16](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/16), [#17](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/17), [#18](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/18), [#19](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/19) and [#20](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/20). The owner has confirmed acceptance of the complete Phase 1 deliverable. The merged scope covers the cryptographic provider and fuzz baseline, key-management contracts, Shamir recovery, seal/bootstrap and quorum controls, the mandatory Shamir 2-of-3 Unsealer with optional disabled-by-default AWS KMS, barrier/AAD/nonce/rotation contracts, and durable redb storage. Phase-specific CI, security-scan and implementation evidence is recorded under each subphase below. **Acceptance does not erase documented boundaries:** the controller crate and storage adapter remain library-level components to be composed through the Phase 2 service; this status does not claim that the Phase 2 server/API already exists, nor does it claim production deployment, FIPS validation or an independent security audit. ADR-0004's numeric AES-GCM rotation threshold/safety margin and nonce-reservation block size remain explicit owner-pending parameters; no defaults have been guessed, and operations depending on them must receive approved explicit values before being enabled.

## Phase overview

| Phase | Name | Community outcome |
|---|---|---|
| 0 | Foundations | Public architecture, threat boundaries, decision records, workspace plan, governance and CI baseline |
| 1 | Seal and encrypted storage | Cryptographic boundary, seal lifecycle, key hierarchy, barrier encryption, recovery and encrypted persistence |
| 2 | [Native API, authentication, authorization and audit](#phase-2-native-api-authentication-authorization-and-audit) | Versioned `/v1` service, ordered TLS request pipeline, authentication, deny-by-default ACL and durable fail-closed audit |
| 3 | PKI engine | Certificate authority workflows, issuance, revocation and interoperability |
| 4 | KV v2 and leases | Versioned key/value storage, concurrency controls and lease lifecycle |
| 5 | Transit | Encryption, decryption, signing, verification, HMAC and key lifecycle services |
| 6 | High availability and recovery | Encrypted Raft, node identity, snapshots, backup/restore and failure recovery |
| 10 | Delivery ecosystem | CLI and deployment packages, public integrations, documentation and the approved UI scope |

Phases are sequential. A later phase does not begin until the active phase's Definition of Done is met and the owner accepts its phase report. The public roadmap omits edition-specific milestones that are not part of Community.

## Phase 0 — Foundations

**Scope:** establish the public Community repository as an independently buildable, clearly governed and security-conscious product baseline. Phase 0 covers repository/migration integrity, public architecture and ADR provenance, Community/Enterprise separation, initial Rust workspace/toolchain, contribution and security policy baselines, and effective GitHub/CI controls. It does not require a completed service, API, CLI, production packaging or Phase 1 cryptographic implementations; those belong to later phase gates.

### Phase 0 Definition of Done

1. **Public repository and provenance.** The curated Community snapshot is in `main`; `MIGRATION.md` identifies the source baseline, migration scope, provenance limits and retained source-repository boundary. No claim is made that source Git history was migrated.
2. **Edition separation.** Community's public scope and dependency direction are documented in [ADR-0008](docs/adr/0008-community-enterprise-boundary.md) and [edition-separation.md](docs/decisions/edition-separation.md). Workspace manifests and CI must build without Enterprise source, private packages, credentials or runtime services.
3. **Decision record completeness.** Community-applicable source decisions are adapted into public ADRs 0001–0025 and classified in [SOURCE-MAP.md](docs/adr/SOURCE-MAP.md). The owner-only repository-administration decision is deliberately not published as a Community product ADR. Approved and pending statuses must be preserved; no pending parameter is silently resolved.
4. **Workspace/toolchain baseline.** The Cargo workspace, committed lockfiles and pinned `rust-toolchain.toml` are present. Locked dependency metadata, formatting, tests, Clippy and the approved MSRV/platform checks run through CI. Planned future crates are not added before their approved roadmap phase.
5. **Governance and main-branch protection.** Changes to `main` flow through pull requests; the active Community ruleset blocks branch deletion and non-fast-forward updates, requires linear history, allows squash merges, and requires the named quality and secret-history checks. The solo-owner zero-approval setting follows [ADR-0011](docs/adr/0011-governance-and-pull-requests.md); it is an explicit solo-development exception, not independent peer review. Ruleset bypass actors must remain absent unless separately approved.
6. **CI and secret-history baseline.** The CI and full-history Gitleaks workflows are enabled for pull requests and pushes to `main`. Both must pass against the exact current `main` commit; a historical run from an earlier SHA is not a substitute.
7. **Public policy/document consistency.** README, architecture overview, roadmap, contribution guidance, security policy, edition-boundary summary, license status and public ADR index accurately distinguish implemented, planned and deferred behavior. Documentation links and anchors pass the repository's link checker.
8. **Sensitive-material hygiene.** Repository ignore rules, test/fuzz conventions and Gitleaks configuration prohibit committing credentials, root material, recovery shares, bootstrap tokens, production data or secret-bearing artifacts. CI fixtures and fuzz corpora use synthetic material only.
9. **Transparent external/legal gates.** Provisional MPL-2.0 status, product-name/trademark status, external contribution terms, vulnerability-disclosure readiness and limits on security claims are documented without being misrepresented as complete.

### Phase 0 evidence on the current Community baseline

- Public migration and repository baseline: [PR #1](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/1), [PR #3](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/3) and [PR #7](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/7).
- Provisional license declaration and status: [PR #4](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/4) and [LICENSE-STATUS.md](LICENSE-STATUS.md).
- Migration workflow cleanup and sensitive-file ignore rules: [PR #5](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/5) and [PR #6](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/6).
- Public ADR carryover and source classification: [PR #8](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/8) and [PR #9](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/9).
- Active main ruleset: `Ferrum Vault Community — Protect main`, ruleset ID `27225364`, enforcement `active`, target `refs/heads/main`; rules: deletion block, non-fast-forward block, linear history, pull request with squash-only merge, and required `Public repository quality gates` plus `Gitleaks — all fetched Git history and refs`. No bypass actors are configured. The main branch is reported protected by GitHub.
- Exact-main validation for commit `dbf40df627b84b12fb726e8fcd0220d2720f7dbf`: [CI #43796677100](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43796677100) and [Secret history scan #43796677103](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43796677103) both passed.

### Phase 0 limitations and separately gated work

These items remain open and must not be hidden, but they do not make the initial Community engineering baseline fictitiously incomplete:

- **Legal review:** qualified review of MPL-2.0 ownership/authority, third-party provenance and contribution terms remains required before commercial launch; see [ADR-0017](docs/adr/0017-community-license.md) and [LICENSE-STATUS.md](LICENSE-STATUS.md).
- **Name clearance:** “Ferrum” remains a working name pending trademark/domain/package-registry clearance before product publication; see [ADR-0012](docs/adr/0012-product-name-and-trademark-clearance.md).
- **Private vulnerability intake:** a confidential reporting channel and response process are not yet configured. This is a blocker before production promotion; public issues must not receive sensitive vulnerability details. See [SECURITY.md](SECURITY.md).
- **External contributions:** no CLA or DCO is adopted. The solo-owner workflow is permitted by ADR-0011; substantial external code contributions may be deferred until inbound contribution terms are approved.
- **Independent review:** the solo-owner self-review period is explicitly allowed for Phases 0–2. A qualified independent human reviewer is required before Phase 3; an independent external security audit remains a separate commercial-MVP gate under ADR-0011.
- **Production-readiness:** passing CI and completing the foundation baseline do not authorize production use and do not imply FIPS validation or an independent security audit.

**Phase 0 closeout status: ACCEPTED by the owner on 2026-11-16.** The owner expressly accepts the Community Phase 0 foundations and the technical/governance baseline documented above. This acceptance satisfies the Phase 0 entry gate for Phase 2. It does not waive separately recorded legal/name-clearance, confidential vulnerability-intake, pre-Phase-3 independent-review or commercial-MVP external-audit gates. It does not represent production authorization, FIPS validation or an independent security audit.

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

**Implementation status — complete within the owner-accepted Phase 1 baseline:** [PR #17](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/17) adds `ferrum-seal` with an Uninitialized/Sealed/Unsealed state machine, one-time expiring bootstrap token, FRS1 ceremony binding, Shamir-backed unseal, zeroizing in-memory root lifecycle and an explicitly configured 2-of-3 authorization gate for `generate-root`, root rotation and root revocation. Missing or invalid quorum configuration fails closed; the generic 5/3 recovery default is not an implicit operation quorum. Derived-credential revocation requires an audit event but no root fragments. Tests cover bootstrap lifetime/expiry/replay, ceremony binding, state transitions, one-share rejection, valid two-share authorization, invalid/duplicate/cross-ceremony shares and derived-credential audit behavior. Fuzz targets exercise seal transitions and root-quorum authorization with synthetic runtime-only material. Exact-head CI [#43542327701](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43542327701) passed 16/16 jobs and Gitleaks [#43542327705](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/actions/runs/43542327705) passed. The controller and the durable redb storage adapter are separate library-level boundaries; the service/API composition belongs to Phase 2. Phase 1 acceptance does not represent an already implemented HTTP endpoint, Phase 2 audit service or production deployment. Recovery fragments must never be committed or exposed in logs/CI.

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

**Status — Phase 0 entry gate satisfied; Phase 2.0 reconciliation in progress. No Phase 2 implementation is claimed by this roadmap entry.** This phase turns the Community libraries into a native, versioned service boundary. It implements the request pipeline and security controls already required by [ADR-0005](docs/adr/0005-request-pipeline-and-fail-closed-audit.md), uses the extension rules in [ADR-0002](docs/adr/0002-async-extension-contracts.md), and follows the native API lifecycle in [ADR-0015](docs/adr/0015-reproducible-builds-and-api-versioning.md).

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

**Explicitly out of scope:** implementing the PKI engine (Phase 3), KV v2 and leases (Phase 4), Transit (Phase 5), encrypted Raft/HA (Phase 6), the web UI (deferred under ADR-0021), and later packaging/orchestration channels. The approved CLI distribution starts in Phase 2 with tar.gz/zip for Linux x86_64/aarch64, universal macOS and Windows x86_64 under ADR-0023; later package-manager/OCI CLI channels remain in the delivery-ecosystem phase. The optional Vault-API compatibility subset in [ADR-0018](docs/adr/0018-vault-api-compatibility-subset.md) is not the native API and must not be pulled into this phase; it is considered only after the native API is stable and its legal-review condition is satisfied. Phase 2 must not add Community dependencies on the private Enterprise edition.

### 2.2 Entry gates and dependencies

The roadmap's phase-sequencing rule remains in force: Phase 2 implementation does not begin until the preceding phase gates have been met and the owner has accepted their reports.

- **Phase 0:** foundations, public workspace/documentation baseline, repository governance and applicable CI Definition of Done are complete and were explicitly owner-accepted on 2026-11-16. The Phase 0 entry gate is satisfied; separately recorded legal, vulnerability-intake, independent-review and external-audit gates remain in force.
- **Phase 1:** complete, merged into `main` and owner-accepted. Phase 2 consumes the accepted cryptographic, seal, Unsealer, barrier and storage contracts. The seal controller and durable storage adapter are library-level components; their composition into the running service is Phase 2 work and must preserve the accepted contracts. ADR-0004's numeric parameters remain explicitly pending; obtain owner approval through an ADR before enabling any service path that depends on them. Do not assign defaults or silently bypass these conditions.
- **Storage and crypto foundations:** the accepted Phase 1.6/1.7 contracts are dependencies for protected state, durable audit coordination and persistence; this does not mean the Phase 2 server itself may store protected plaintext in generic KV.
- **Design gate 2.0:** preserve the existing owner-approved Phase 2 architecture and complete the Community contracts before dependent implementation begins. On 2026-11-16 the owner explicitly delegated missing low-level technical details to the architect. Those new Community defaults are separately recorded as delegated technical selections in ADR-0026–0029, not misattributed to the original source baseline. No prior approval is re-selected or weakened; any conflict with an approved ADR must be resolved in favor of that ADR before implementation.
- **Edition boundary:** the service must build and operate without Enterprise code, credentials, private packages or services.

Subphase dependencies are sequential where security decisions require it: 2.0 precedes all implementation; 2.1 precedes transport integration; 2.2 establishes the request context and ordered pipeline used by 2.3–2.5; authentication (2.3) precedes identity-based authorization (2.4); the audit contract (2.5) must be integrated before sensitive handlers are enabled; 2.6 validates the complete vertical path. Work may proceed in parallel only where these contracts are already approved and no dependency is bypassed.

### 2.3 Subphases and their Definition of Done

#### 2.0 — Approved-design carryover and delegated API/security contract baseline

**Decision register and detailed contracts:** [Phase 2.0 decision register](docs/phase-2/decision-register.md) and [approved Community design carryover](docs/phase-2/approved-design-carryover.md) preserve the owner-approved architecture. The detailed implementation defaults explicitly delegated on 2026-11-16 are recorded in [service-contract.md](docs/phase-2/service-contract.md), [configuration-contract.md](docs/phase-2/configuration-contract.md), [OpenAPI 3.2.1](docs/phase-2/openapi.yaml), [proto3 IDL](proto/ferrum/v1/service.proto) and ADR-0026–0029. They define exact operations/routes, wire schemas, shared error semantics, credentials, ACL grammar, rate/resource limits, sealed-mode access, TLS/configuration, audit/outbox/idempotency and lifecycle behavior. **Subphase 2.0 is a documentation/contract validation and acceptance gate, not a fresh architecture questionnaire.**

**Scope:** preserve all owner-approved requirements, apply the owner's explicit 2026-11-16 delegation to select missing low-level Community defaults, and publish their provenance, wire/configuration contracts and security/test mapping. New delegated selections must be labelled as such and must not be described as already present in the source baseline. Existing ADRs remain superior in a conflict.

**Definition of Done:**
- The exact Community operation catalog, routes, request/response schemas, RPCs and error mapping are defined in OpenAPI/proto and [ADR-0026](docs/adr/0026-phase-2-native-service-contracts.md).
- Authentication, credential lifetimes, ACL grammar, canonicalization, request/rate limits and sealed-mode allowlist are defined by [ADR-0027](docs/adr/0027-phase-2-auth-acl-and-resource-controls.md).
- Durable audit event/hash-chain, idempotency, outbox and recovery semantics are defined by [ADR-0028](docs/adr/0028-phase-2-durable-audit-and-outbox.md).
- TLS listener/certificate lifecycle, strict configuration, file permissions and graceful shutdown are defined by [ADR-0029](docs/adr/0029-phase-2-server-tls-and-configuration.md).
- The existing ADR-0005 security pipeline and all previously approved constraints remain unchanged; delegated selections are separately attributed and tested.
- OpenAPI/proto/config documentation validation, link checks, exact-head CI and Gitleaks pass before the owner-acceptance gate.

#### 2.1 — Native `/v1` API and contract definitions

**Scope:** implement the contract defined by [ADR-0026](docs/adr/0026-phase-2-native-service-contracts.md), [OpenAPI 3.2.1](docs/phase-2/openapi.yaml) and [proto3 IDL](proto/ferrum/v1/service.proto). ADR-0015's `/v1`, semantic-versioning and two-minor deprecation requirements remain binding. The exact detailed routes and wire forms are delegated technical selections, not source-baseline decisions.

**Definition of Done:**
- Every Phase 2 endpoint has a documented method, canonical route, input/output schema, error behavior and security classification.
- Each endpoint identifies whether it is available while sealed, which authentication and ACL checks apply, and which audit events are mandatory.
- OpenAPI and proto3 artifacts are linted, generated bindings are consistent, and HTTP/gRPC operations and domain-error semantics match. Breaking changes require a new version or a reviewed compatibility plan.
- Versioning and deprecation rules are covered by automated contract tests.
- Unsupported and deferred endpoints are documented; future Phase 3–6 engines and the optional Vault compatibility surface are not represented as implemented.

#### 2.2 — TLS server and ordered request pipeline

**Scope:** provide both approved native transports through the single listener and strict TLS/configuration profile defined by [ADR-0029](docs/adr/0029-phase-2-server-tls-and-configuration.md), sharing one authoritative ADR-0005 pipeline per ADR-0025. Use TLS 1.3/rustls, server request IDs, bounded request size/time, pre-auth IP limiting, seal-state gating and the exact six-operation sealed allowlist. Pipeline order must not be reordered or bypassed.

**Definition of Done:**
- The selected transport starts with TLS 1.3 and rejects invalid/untrusted transport configuration according to the approved configuration contract.
- Each request receives a server-generated request ID and bounded resource/deadline context.
- The order of all pipeline stages is verified by integration tests, including early rejection paths.
- IP-based pre-authentication rate limiting uses the trusted socket peer by default and only explicitly configured proxy CIDRs/RFC 7239 `Forwarded` handling from ADR-0027/0029; spoofable headers are never authoritative.
- Sealed-mode behavior is deny-by-default except for the explicit approved allowlist.
- Cancellation, timeout and connection termination leave state and resources consistent; applicable concurrency/failure tests are included.

#### 2.3 — Authentication and identity lifecycle

**Scope:** implement the owner-approved MVP methods using the credential and lifecycle details selected in [ADR-0027](docs/adr/0027-phase-2-auth-acl-and-resource-controls.md): token, AppRole, mTLS client certificate, and username/password with Argon2id. OIDC, Kubernetes authentication and LDAP remain deferred. Identity is server-owned; post-auth identity limits apply. Dynamic extensions retain ADR-0002's async + `Send + Sync` contract and cancellation/error/concurrency requirements.

**Definition of Done:**
- The four owner-approved MVP methods (token, AppRole, mTLS client certificate and username/password with Argon2id) implement the credential and lifecycle details selected under delegation in ADR-0027 and the Phase 2 service contract. Bootstrap token issuance is one-time; approved expiry, renewal, revocation and replay protections are preserved. OIDC, Kubernetes authentication and LDAP are not enabled in the MVP.
- Unauthenticated, malformed, expired, revoked, replayed and otherwise invalid credentials fail closed and do not reach protected handlers.
- Identity is produced by the authentication boundary; client-supplied identity or tenant fields cannot override it.
- Identity-based rate limiting is enforced after successful authentication.
- Secret credentials and tokens are not written to logs, audit payloads, error bodies, test artifacts or fuzz corpora.
- Provider contract tests prove the required async/dynamic compatibility and cancellation behavior.

#### 2.4 — Canonical routing and deny-by-default authorization

**Scope:** evaluate authenticated identities against the canonical route/action/resource model and the deliberately small versioned ACL language selected in ADR-0027. Community's logical tenant remains `root`; no client-controlled tenant selector or implicit allow rule is introduced.

**Definition of Done:**
- Every protected route is covered by an explicit policy decision; missing, malformed, unavailable or indeterminate policy state denies access.
- Route canonicalization occurs before policy evaluation and is consistent between routing, authorization and audit.
- Tests cover path aliases, encoding/normalization edge cases, method/action confusion, policy absence, conflicting rules and attempted privilege escalation according to the ACL grammar and semantics specified in delegated ADR-0027 and the Phase 2 service contract.
- The authenticated identity and `root` tenant context are derived server-side.
- Authorization decisions are explainable through non-secret diagnostics/audit references without disclosing credentials or protected values.

#### 2.5 — Durable audit and fail-closed operation boundary

**Scope:** implement ADR-0005 using the detailed event/hash-chain/outbox/idempotency/reconciliation contract in [ADR-0028](docs/adr/0028-phase-2-durable-audit-and-outbox.md). Keep the minimum JSON hash-chain file plus stdout/syslog destinations and 90-day default. Intent remains durable before sensitive side effects or protected disclosure; failures block the operation.

**Definition of Done:**
- Audit event schema, canonical serialization, hash-chain construction/verification, append/concurrency behavior, sink configuration and retention enforcement preserve ADR-0005 and implement the detailed contract selected in delegated ADR-0028.
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

The following required boundaries are normatively specified by service-contract.md, configuration-contract.md, OpenAPI and proto3 IDL, with the decisions traced through ADR-0002/0005/0015/0025–0029. Rust type names and crate boundaries remain implementation details; the externally observable contracts are fixed.

| Boundary | Required contract |
|---|---|
| Listener and transport | Single TLS 1.3/rustls listener for HTTP/JSON + gRPC, ALPN `h2`/`http/1.1`, no plaintext or 0-RTT, request lifecycle and cancellation (ADR-0026/0029) |
| Request context | Server-generated request ID, trusted peer/client-address context, deadline and size bounds, seal state, authenticated principal when available, canonical route/action and Community tenant `root` |
| API handler | Versioned request/response contract, typed error behavior, no bypass around pipeline controls |
| Authentication extension | Credential validation, trusted identity production, typed failure behavior, cancellation and concurrency guarantees; dynamic plugins follow ADR-0002 |
| Rate limiting | Separate pre-auth socket-peer IP and post-auth identity buckets; trusted proxy CIDRs and bounded RFC 7239 parsing; mandatory limits/fail-closed backend (ADR-0027) |
| Authorization | Canonical resource/action + trusted identity → explicit allow/deny; unavailable or indeterminate state denies |
| Audit sink | Durable intent/outcome append and verification contract, sink failure semantics, cancellation behavior, and no secret disclosure |
| Configuration | Strict TOML with safe defaults and explicit required root 2-of-3 quorum; invalid/unsafe settings fail startup or disable the affected capability closed (ADR-0029) |

### 2.5 Provenance and delegated decision control

The [SOURCE-MAP](docs/adr/SOURCE-MAP.md) explains which Community ADRs carry forward the owner's original architecture. The abbreviated source records establish the binding high-level decisions; they do not contain all the detailed values and API catalog fields that this Phase 2 contract now specifies.

On 2026-11-16 the owner explicitly delegated selection of the missing low-level Community details to the technical architect. The selected defaults are recorded separately in ADR-0026 through ADR-0029 and the machine-readable contracts. They are **new delegated technical selections**, not retroactive claims that those exact route names, schemas, numeric defaults or audit encodings were present in the source baseline.

Decision precedence is strict: existing owner-approved Community ADRs first; delegated ADR-0026–0029 and their contracts second; implementation details third. A conflict with an owner-approved ADR blocks the dependent implementation until explicitly resolved. A delegated detail may be changed later only through a reviewed superseding ADR with compatibility and threat impact.

Carry-forward invariants that must never be weakened:

1. HTTP/JSON and gRPC share the one ADR-0005 pipeline; `/v1`, semver and two-minor deprecation remain from ADR-0015.
2. The authentication MVP remains token, AppRole, mTLS and username/password Argon2id; OIDC/Kubernetes/LDAP remain excluded.
3. Community remains single-tenant `root`, derived only from trusted server context.
4. Shamir 2-of-3 remains the mandatory default Unsealer; root operations independently require explicit 2-of-3 root quorum; optional AWS KMS stays disabled by default without fallback.
5. ADR-0005's pipeline ordering, durable intent/outcome, fail-closed behavior, minimum audit destinations and 90-day default retention remain binding.
6. ADR-0002 async + `Send + Sync`, ADR-0003 storage semantics, ADR-0010 verification requirements, ADR-0021 no-web-UI MVP, ADR-0022 distribution/hardening and ADR-0023 Phase 2 CLI archive scope remain unchanged.
7. PKI, KV v2/leases, Transit and encrypted Raft/HA stay in their later roadmap phases; no Enterprise-only API, dependency, service or design enters Community.

Detailed implementation changes must link to the relevant delegated ADR and update both the machine-readable contract and security tests. No runtime subphase proceeds until Phase 2.0 validation and owner acceptance.

### 2.6 Required test and evidence strategy

Apply [ADR-0010](docs/adr/0010-testing-and-security-evidence.md) to each subphase; do not defer fuzzing or negative security tests until the end.

- **Unit tests:** request parsing and validation, route canonicalization, pipeline ordering, rate-limit boundaries, credential lifecycle, identity construction, policy evaluation/deny-by-default, audit serialization/hash-chain verification and configuration validation.
- **Property tests (proptest):** canonical route invariants, policy decision invariants, credential/event codec round trips, audit-chain continuity, and rate-limit/state invariants where the implementation has deterministic properties.
- **Coverage-guided fuzzing (cargo-fuzz):** all untrusted parsers and decoders introduced by the chosen transport/schema, credential formats, route canonicalization, policy parser, audit record decoder and any security-sensitive state transition. Fuzz targets use synthetic material only; corpora must not contain valid credentials, secrets, recovery shares or production audit data. Add a deterministic regression test for every discovered defect.
- **Integration tests:** a real in-process TLS 1.3 listener carrying both HTTP/JSON and gRPC, request middleware, trusted-proxy boundary, storage/seal integration, authentication providers, ACL decisions, rate limiter and audit sinks. Include process restart and injected sink/storage failure where persistence is involved.
- **Security tests:** unauthorized/unauthenticated requests, expired/revoked/replayed credentials, spoofed client-address headers, path and encoding ambiguity, policy bypass, privilege escalation, sealed-mode bypass, oversized/slow requests, cancellation, secret leakage and audit failure. Run equivalent negative suites through both selected transports (HTTP/JSON and gRPC), and prove neither adapter bypasses the common pipeline.
- **End-to-end tests:** exercise the actual listener and every approved Phase 2 route across success and failure paths. Prove that no protected handler or secret response is reachable when any required earlier gate denies or when required audit intent cannot be persisted.
- **Concurrency and runtime tools:** use Loom where shared state/concurrency models make it appropriate, Miri for eligible pure-Rust code, failure injection for persistence and cancellation, and Criterion for performance-sensitive paths. Document justified exclusions rather than claiming unrun techniques.
- **Coverage and CI:** meet the ADR-0010 target of at least 90% measured coverage for `crypto`, `seal`, `policy`, `auth` and `audit` components, with exclusions documented and measured against the correct crate/module boundaries. CI must enforce formatting, clippy with warnings denied, tests, dependency policy/audit, measured coverage and bounded fuzz smoke. Longer fuzz campaigns run on the scheduled/manual workflow. Run the applicable supported-platform and MSRV matrix.
- **Evidence hygiene:** retain exact-head CI links, coverage reports, fuzz artifacts, threat-model changes, security checklist, configuration/runbook evidence and a list of limitations. Never use real credentials or production secrets in CI fixtures or artifacts.

### 2.7 Phase 2 acceptance criteria

Phase 2 is complete only when all of the following are true and the owner accepts the phase report:

1. The Phase 2 entry gates are satisfied and every implementation-affecting owner decision is resolved in an ADR or explicitly excluded with its dependent feature disabled.
2. The documented native `/v1` API catalog and schemas match the running service; semantic versioning and the two-minor deprecation policy are enforced by contract tests.
3. The actual service enforces the full ADR-0005 pipeline in the approved order, using TLS 1.3/rustls and both approved native transports (HTTP/JSON and gRPC) through the shared pipeline.
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
