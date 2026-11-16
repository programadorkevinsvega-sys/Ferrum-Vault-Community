# Phase 2.0 — Owner decision register and contract baseline

- **Status:** In progress. D2.0-01 (dual HTTP/JSON + gRPC transports with one shared security pipeline) is owner-approved in [ADR-0025](../adr/0025-dual-api-transports-shared-security-pipeline.md); D2.0-02 through D2.0-11 remain pending. **Subphase 2.0 is not complete.**
- **Scope:** Ferrum Vault Community only.
- **Parent:** [ROADMAP Phase 2](../../ROADMAP.md#phase-2-native-api-authentication-authorization-and-audit).
- **Purpose:** Give the owner a concrete, traceable decision surface for Phase 2.0. This register records approved constraints, candidate operations, contract boundaries and unresolved choices. It is not an ADR and does not approve any candidate choice by implication.

## 1. Decision-control rules

1. Existing owner-approved ADR requirements remain binding. Phase 2.0 must apply them, not reopen or silently weaken them.
2. Only the transport decision explicitly recorded in ADR-0025 is approved: both HTTP/JSON and gRPC share one authoritative security pipeline. Other options below are candidates only; no schema tooling, credential type, policy grammar, numeric limit, default, endpoint or audit algorithm is selected by this register.
3. An implementation-affecting choice becomes binding only after the owner approves a new ADR or a superseding ADR and that decision is merged into Community main.
4. A feature with an unresolved decision must remain disabled or outside the approved scope. It must not gain a permissive fallback.
5. Phase 2.0 is design and approval work. It does not authorize Phase 2.1–2.6 runtime implementation. Phase 0's explicit owner closeout gate remains visible in the roadmap until recorded.

## 2. Binding constraints inherited from approved ADRs

| Constraint | Binding requirement | Source |
|---|---|---|
| Native transports | Expose both HTTP/JSON and gRPC; transport adapters share one authoritative security pipeline and equivalent security semantics | [ADR-0025](../adr/0025-dual-api-transports-shared-security-pipeline.md) |
| Request pipeline | Preserve the approved order: TLS 1.3 listener using rustls; HTTP/gRPC server and request ID; request size/time limits; IP pre-auth rate limit; local seal check; authentication; identity rate limit; canonical route/ACL; handler; durable audit before/after sensitive operations | [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md) |
| Fail-closed audit | If required audit intent cannot be persisted, do not perform the sensitive operation or disclose protected read data; configured sink failure blocks the operation | [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md) |
| Audit baseline | JSON file with hash-chain integrity and stdout/syslog are the minimum named destinations; retention is configurable with a 90-day default. Details not explicitly defined by ADR-0005 remain open | [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md) |
| Native API lifecycle | Native API is under /v1, uses semantic versioning and a two-minor-version deprecation policy | [ADR-0015](../adr/0015-reproducible-builds-and-api-versioning.md) |
| Dynamic extensions | Dynamically dispatched auth/audit/provider extensions use async traits with Send + Sync; document cancellation, lifetimes, errors, concurrency and security guarantees | [ADR-0002](../adr/0002-async-extension-contracts.md) |
| Storage | Protected values are encrypted before generic storage; initial Community backend is redb and the shared backend contract is linearizable | [ADR-0003](../adr/0003-storage-backend-contract.md) |
| Community tenant | Community remains single-tenant; logical tenant is root, derived from trusted authenticated/authorized server context. No client-selected tenant | [ADR-0019](../adr/0019-community-tenant-model.md) |
| Seal provider | Shamir 2-of-3 is the mandatory default Unsealer. AWS KMS is optional, feature-gated and disabled by default; no silent provider fallback | [ADR-0024](../adr/0024-unsealer-port-and-optional-aws-kms.md) |
| Compatibility surface | Optional Vault API subset is later, after the native API is stable and legal review is complete; it is not Phase 2's native API | [ADR-0018](../adr/0018-vault-api-compatibility-subset.md) |
| Administrative UI | MVP does not include a web UI; a later UI uses this same server/API and never replaces server-side controls | [ADR-0021](../adr/0021-user-interface.md) |
| Verification | Apply unit, property, fuzz, integration, failure-injection, concurrency where appropriate, Miri where applicable, negative-security, E2E, benchmark and interoperability evidence; target 90% measured coverage for crypto, seal, policy, auth and audit | [ADR-0010](../adr/0010-testing-and-security-evidence.md) |

## 3. Candidate native operation inventory — owner review required

This is an operation inventory, not an approved endpoint list. It deliberately does not assign HTTP methods, paths, schemas or response fields. Inclusion and exclusion must be decided by the owner before Phase 2.1.

| Area | Candidate operation family | Existing dependency / boundary | Phase 2.0 status |
|---|---|---|---|
| Service diagnostics | Process liveness, readiness and non-secret service diagnostics | Server lifecycle and dependency health are not yet implemented | Inclusion and information exposed pending |
| Seal state | Read current seal/bootstrap state | ferrum-seal library; response may reveal operational state | Inclusion and sealed availability pending |
| Bootstrap | Initialize/bootstrap the root ceremony and persist its state | Existing Phase 1 seal/recovery contracts; durable service composition required | Inclusion, caller authority and one-time behavior pending |
| Unseal | Submit the mandatory Shamir 2-of-3 unseal material | Unsealer port; shares are sensitive and must never enter logs, audit bodies or artifacts | Inclusion, request representation and throttling pending |
| Seal | Request a transition to Sealed | SealController boundary; mutation requires authorization and audit under approved rules | Inclusion and authority pending |
| Root lifecycle | Generate/rotate/revoke root operations | Existing 2-of-3 RootQuorumPolicy; sensitive root material handling must be specified | Which operations are exposed over the API pending |
| Authentication | Issue/inspect/renew/revoke credentials, if selected | Credential format, issuer and lifecycle are undecided | Mechanism and operation subset pending |
| Identity administration | Create/disable/inspect identities, if selected | Trusted server-side principal model is undecided | Inclusion and authority pending |
| Policy administration | Create/read/update/delete/list ACL policies, if selected | Policy grammar, storage and administrative recovery are undecided | Inclusion and operation subset pending |
| Audit administration | Verify audit-chain integrity and inspect non-secret sink status, if selected | Audit schema, verification and operational permissions are undecided | Whether exposed through API or operator tooling pending |

### Explicit Phase 2 exclusions

The following are not native Phase 2 operations and must not be represented as implemented or pulled into the endpoint catalog without a roadmap/ADR change:

- KV v2 and lease engine operations (Phase 4).
- PKI engine operations (Phase 3).
- Transit engine operations (Phase 5).
- Encrypted Raft/HA operations (Phase 6).
- CLI, UI and distribution/packaging workflows (their later roadmap phases).
- Vault API compatibility routes (later optional work under ADR-0018).

## 4. Route security-classification worksheet

The following categories must be populated for every selected operation before its route contract is approved. The entries below are intentionally unresolved; they are not permissive defaults.

| Operation category | Available while sealed? | Authentication | Authorization | Required audit intent/outcome | Additional invariant |
|---|---|---|---|---|---|
| Liveness/readiness | Owner must distinguish liveness from dependency readiness and approve the fields | Pending | Pending | Pending | Must not disclose secrets, credentials, shares or protected values |
| Seal-state diagnostics | Pending | Pending | Pending | Pending | State disclosure and information exposure require explicit review |
| Bootstrap | Only its necessary pre-unseal lifecycle can be considered; exact rule pending | Bootstrap authority pending | Pending | Sensitive lifecycle audit per approved contract | One-time/replay protection; never persist or log shares/tokens in plaintext |
| Unseal | Must be reachable in the sealed state if the API owns unseal; exact exposure pending | Shamir 2-of-3 proof is mandatory; transport/auth envelope pending | Pending | Intent/outcome semantics pending | Reject wrong, duplicate, mixed-ceremony or insufficient shares; no provider fallback |
| Seal | Not applicable as an unsealed-only action; precise behavior pending | Pending | Pending | Required for sensitive mutation | Failure must not leave a partially transitioned state |
| Root lifecycle | Pending | Separate 2-of-3 root-operation quorum remains mandatory | Pending | Required for sensitive mutation | API auth must not replace or weaken the independent quorum |
| Credential/identity changes | Pending | Pending | Pending | Required for security-sensitive changes | Secret credential material never appears in logs or audit payloads |
| ACL policy changes | Pending | Pending | Administrative policy is deny-by-default | Required | Policy change/lockout recovery and atomicity must be defined |
| Audit verification/diagnostics | Pending | Pending | Pending | Avoid recursive audit requirements that prevent recovery; exact approach pending | Diagnostics must not expose protected audit contents or bypass sink-failure behavior |

## 5. Owner-pending decision register

D2.0-01 is **Owner-approved** in ADR-0025. D2.0-02 through D2.0-11 remain **Pending owner decision**. Remaining alternatives are prompts for evaluation, not recommendations, defaults or commitments.

### D2.0-01 — Transport and server implementation

- **Owner decision:** **APPROVED — HTTP/JSON and gRPC are both native Phase 2 MVP transports.** They must share one authoritative security pipeline and logical request/security context; transport adapters may only perform protocol-specific decoding/encoding and may not duplicate or weaken security controls.
- **ADR:** [ADR-0025 — Dual native API transports with a shared security pipeline](../adr/0025-dual-api-transports-shared-security-pipeline.md).
- **Must preserve:** TLS 1.3 via rustls, the exact ADR-0005 pipeline order and equivalent security semantics across both transports.
- **Still open:** server/framework selection, listener topology, JSON schema/source-of-truth tooling, gRPC IDL/serialization tooling, cross-transport error mapping and operation-by-operation transport coverage.
- **Approval date:** 2026-11-15.

### D2.0-02 — Wire/schema and error contract

- **Required decision:** HTTP/JSON contract schema/source of truth, gRPC IDL/serialization schema and the mapping of validation/typed errors across the two transports.
- **Candidate directions to evaluate:** separately maintained or generated HTTP/JSON schemas; a gRPC IDL and corresponding generation approach; an explicitly documented shared error taxonomy.
- **Must preserve:** HTTP uses JSON representations, the native HTTP API follows /v1, internal typed errors remain stable and responses never disclose secrets.
- **Impact:** API clients, compatibility tests, generated code, parser/fuzz scope and error disclosure.
- **Not selected:** schema language/tooling, gRPC IDL, code generator, exact error fields or HTTP/gRPC status mapping.

### D2.0-03 — Native endpoint and operation catalog

- **Required decision:** select the Phase 2 system/administration operations from §3, state their exact inclusion/exclusion, and approve their route/method names in the API contract stage.
- **Candidate scope:** service diagnostics; seal/bootstrap/unseal/seal lifecycle; selected root lifecycle operations; selected auth/identity operations; selected policy administration; optional audit diagnostics.
- **Must preserve:** no KV, PKI, Transit, HA or Vault-compatibility routes in this phase unless a separately approved roadmap change is made.
- **Impact:** exposed attack surface and dependencies for 2.1–2.6.
- **Not selected:** route names, methods, payloads or final MVP subset.

### D2.0-04 — Authentication mechanism and credential representation

- **Required decision:** supported authentication method(s), credential entropy/representation, transport, storage and validation boundary.
- **Candidate directions to evaluate:** opaque bearer credentials issued by the service; mutual-TLS client identities; an external identity-provider integration; a deliberately smaller first-release mechanism.
- **Must preserve:** authentication creates the trusted principal; clients cannot supply/override principal or tenant; credentials are never logged or placed in audit bodies; failed authentication is fail-closed.
- **Impact:** bootstrap, credential theft/replay threats, renewal/revocation, storage encryption and integration tests.
- **Not selected:** token format, signing/MAC algorithm, password use, external provider, credential TTL or storage format.

### D2.0-05 — Identity and credential lifecycle

- **Required decision:** principal model and issuance/bootstrap, expiry, renewal, revocation, rotation, invalidation, replay and recovery semantics.
- **Candidate fields for review only:** stable subject identifier, credential identifier, authentication method and lifecycle timestamps.
- **Must preserve:** server-generated identity context and ADR-0002 async extension guarantees for dynamically dispatched authenticators.
- **Impact:** session invalidation, concurrent requests, audit attribution and identity-rate-limit keys.
- **Not selected:** identity schema, token/session model, lifetime values or revocation data structure.

### D2.0-06 — ACL and canonical resource semantics

- **Required decision:** policy grammar, resource/path representation, actions/capabilities, matching and precedence, policy versioning/update behavior, administrative bootstrap and lockout recovery.
- **Candidate directions to evaluate:** exact canonical paths; segment-aware path patterns; resource/action tuples with explicit capabilities.
- **Must preserve:** canonicalization before policy evaluation, deny-by-default, Community tenant root from trusted context and no client-selected tenant.
- **Impact:** confused-deputy/path traversal, privilege escalation, policy parser fuzzing and policy update atomicity.
- **Not selected:** grammar, wildcard semantics, capability vocabulary, precedence or policy storage shape.

### D2.0-07 — Rate limiting, trusted proxy and request bounds

- **Required decision:** pre-auth source identity, post-auth principal key, algorithm/window/burst, local versus shared scope, trusted-proxy model, body-size limits, timeouts and failure behavior.
- **Candidate directions to evaluate:** fixed window, sliding window or token bucket; direct-peer-only client address or explicitly configured trusted proxy chain.
- **Must preserve:** separate pre-auth IP and post-auth identity gates in ADR-0005; never trust spoofable forwarding headers by default.
- **Impact:** denial-of-service resistance, multi-process consistency, false blocking and observability.
- **Not selected:** numeric quotas, burst, time windows, maximum sizes, deadlines, storage backend or proxy CIDRs.

### D2.0-08 — Sealed-mode allowlist

- **Required decision:** exact operations and response fields that remain available while sealed.
- **Candidate areas for review:** liveness; carefully minimized readiness; seal-state status; the unseal operation itself.
- **Must preserve:** all unspecified operations are unavailable while sealed; allowlist entries must be demonstrably non-sensitive and minimal.
- **Impact:** information disclosure, bootstrap exposure and recovery availability.
- **Not selected:** any route, response field or authentication exception.

### D2.0-09 — TLS certificate and trust lifecycle

- **Required decision:** certificate/key provisioning, trust roots, reload/rotation and operator error behavior.
- **Candidate directions to evaluate:** operator-managed PEM files; platform-managed certificate material; another explicitly justified provider.
- **Must preserve:** TLS 1.3 with rustls; invalid required TLS configuration fails closed; private keys are not logged or included in diagnostics.
- **Impact:** deployment, rotation downtime, trust boundaries and secret handling.
- **Not selected:** provisioning mechanism, file paths, formats, reload semantics or trust-root defaults.

### D2.0-10 — Audit event, hash chain and sink durability

- **Required decision:** event schema, canonical serialization, hash algorithm/chain metadata, append atomicity, fsync/durability boundary, sink configuration, file rotation/archival/export and verification procedure.
- **Must preserve:** ADR-0005 minimum destinations and 90-day configurable default; intent before sensitive action/read disclosure; durable outcome after; fail closed when a required write cannot be persisted.
- **Impact:** tamper evidence, truncation/reordering detection, crash recovery, storage pressure and forensic usability.
- **Not selected:** hash algorithm, canonical encoding, exact event fields, file format details, fsync policy, sink fan-out policy, archive mechanism or verification CLI/API.

### D2.0-11 — Audit/state coordination and service operations

- **Required decision:** transaction boundary for audit plus state; use of outbox/idempotency/reconciliation when the same transaction cannot cover both; configuration source/format; startup validation; health/readiness meanings; graceful shutdown and supported deployment assumptions.
- **Candidate directions to evaluate:** a shared storage transaction where supported; durable outbox with reconciliation when state and audit sinks are separate.
- **Must preserve:** no sensitive operation without durable audit intent; no silent success when outcome recording is required; unsafe or incomplete security configuration fails closed.
- **Impact:** crash consistency, duplicate/missing audit events, recovery procedure and operator responsibilities.
- **Not selected:** outbox schema, idempotency key format, retry policy, configuration format, readiness dependencies or shutdown deadline.

## 6. Logical interface and contract boundaries

These are responsibilities only. They do not prescribe Rust type names, signatures, crate boundaries or wire formats.

| Boundary | Contract responsibilities | Required failure behavior |
|---|---|---|
| Listener/transport | TLS 1.3/rustls, selected protocol(s), peer identity, connection lifecycle, cancellation | Reject invalid TLS and malformed transport input; no plaintext downgrade |
| Request context | Server request ID, trusted peer address, deadline/size budget, seal state, authenticated principal when available, canonical resource/action, tenant root | Context is server-owned; never accept client-provided principal/tenant as authoritative |
| API handler | Versioned operation contract, input validation, typed errors | Cannot bypass pipeline or return protected data before authorization/audit gates |
| Authentication | Credential validation and trusted principal creation; dynamic extension contract per ADR-0002 | Invalid, expired, revoked, replayed, unavailable or indeterminate auth fails closed |
| Rate limiter | Pre-auth source and post-auth identity controls | Backend/state failure behavior must be approved; never silently disable limits |
| Authorization | Canonical resource/action + trusted principal -> explicit allow/deny | Missing, malformed, unavailable or indeterminate policy denies |
| Seal lifecycle | Adapter over accepted Phase 1 seal/Unsealer contracts | Shamir 2-of-3 remains default; alternate provider explicit; no fallback |
| Storage | Uses accepted redb backend contracts; ciphertext before generic KV | Atomicity/linearizability claims only where conformance evidence supports them |
| Audit | Durable intent/outcome append and verification; cancellation and sink semantics | Required write failure blocks mutation or protected disclosure |
| Configuration | Parse, validate and source secrets safely | Incomplete/unsafe required security configuration prevents startup or affected operation |

## 7. Security invariants and threat-model updates

Phase 2.0 records the following threat additions for the Phase 2 threat-model update; each requires a mitigation and test owner before implementation:

- Remote unauthenticated attacker: parser exploitation, request flooding, oversized/slow requests and resource exhaustion.
- Credential holder or thief: credential theft, replay, expiry/revocation races and identity spoofing.
- Untrusted client or reverse proxy: spoofed forwarded address, request-context confusion and principal/tenant substitution.
- Path/route ambiguity: encoded separators, normalization differences, method/action confusion, aliases and policy bypass.
- Malicious or stale policy state: missing policy, conflicting policy, policy update races and administrative lockout.
- Sealed-state attacker: probing protected operations or exploiting an overly broad sealed allowlist.
- Audit/storage failure: unavailable sinks, partial append, concurrent append, power interruption, truncation/reordering and state/audit divergence.
- Operator/configuration error: unsafe TLS setup, trust-root mistakes, weak credential handling and disabled security controls.

The approved invariants remain: deny-by-default authorization; server-owned request/identity/tenant context; mandatory Shamir 2-of-3 unseal default; optional AWS KMS disabled by default; and fail-closed durable audit for sensitive operations.

## 8. Test and evidence mapping

Apply ADR-0010 at the subphase that introduces each boundary. No parser, protocol or security state machine is exempt from fuzzing merely because the feature is early.

| Boundary/decision | Minimum evidence to add when implemented |
|---|---|
| Transport and wire schema | Unit validation; parser fuzzing; TLS listener integration; malformed/oversized/slow request tests; protocol negative tests |
| Request context and canonical routing | Property tests for normalization/canonicalization; fuzz encoded paths; integration tests for aliases and spoofed context |
| Authentication and lifecycle | Unit/property tests for lifecycle transitions; fuzz credential codecs; tests for invalid/expired/revoked/replayed credentials, cancellation and concurrency |
| Rate limiting | Boundary/property tests for windows/bursts; concurrent tests; trusted-proxy spoofing tests; outage/fail-closed tests |
| ACL | Property tests for decision invariants; fuzz policy parser; deny-by-default, precedence, privilege escalation and path confusion tests |
| Seal and root lifecycle adapters | Existing Phase 1 regression suite plus service-level tests for Shamir 2-of-3, independent root-operation quorum, sealed gating and no fallback |
| Audit | Unit/property tests for serialization and chain continuity; fuzz decoder; append concurrency; tamper/truncation/reordering; sink failure; crash/restart and audit/state reconciliation |
| Full vertical path | E2E against actual TLS listener covering every approved operation and all earlier-stage rejection paths |

Every discovered defect becomes a deterministic regression test. Test data, fuzz corpora, logs, artifacts and audit fixtures use synthetic material only. Coverage target remains at least 90% for crypto, seal, policy, auth and audit as stated by ADR-0010; measured reports must be supplied rather than inferred from test counts.

## 9. Owner decision and approval record

Complete one row per decision. A blank or "deferred" row is not approval; a dependent feature stays disabled until its decision is approved.

| Decision ID | Owner selection / explicit exclusion | Rationale and trade-offs | ADR reference | Approval date |
|---|---|---|---|---|
| D2.0-01 | HTTP/JSON + gRPC; one shared authoritative security pipeline | Two native access transports without duplicated/weaker security controls | [ADR-0025](../adr/0025-dual-api-transports-shared-security-pipeline.md) | 2026-11-15 |
| D2.0-02 | Pending | Pending | Pending | Pending |
| D2.0-03 | Pending | Pending | Pending | Pending |
| D2.0-04 | Pending | Pending | Pending | Pending |
| D2.0-05 | Pending | Pending | Pending | Pending |
| D2.0-06 | Pending | Pending | Pending | Pending |
| D2.0-07 | Pending | Pending | Pending | Pending |
| D2.0-08 | Pending | Pending | Pending | Pending |
| D2.0-09 | Pending | Pending | Pending | Pending |
| D2.0-10 | Pending | Pending | Pending | Pending |
| D2.0-11 | Pending | Pending | Pending | Pending |

## 10. Phase 2.0 acceptance checklist

- [ ] Owner approves the final native operation catalog and explicit exclusions.
- [ ] Every decision D2.0-01 through D2.0-11 is owner-approved or explicitly deferred with dependent feature disabled.
- [ ] Any change to an existing approved requirement has a new/superseding ADR; existing requirements are not silently weakened.
- [ ] Every selected operation has a completed seal/authentication/authorization/audit classification.
- [ ] Logical interface contracts and request-pipeline invariants map to concrete tests and responsible subphases.
- [ ] Threat-model changes, residual risks and operational dependencies are recorded.
- [ ] Roadmap and ADR index link to the approved records.
- [ ] Phase 0 owner closeout gate is recorded before Phase 2.1 runtime implementation begins.

**Current result:** the design register and candidate inventory are prepared for review. Because all owner-pending selections remain pending, Phase 2.0 is **not yet complete**, and no Phase 2 runtime implementation is authorized by this document.
