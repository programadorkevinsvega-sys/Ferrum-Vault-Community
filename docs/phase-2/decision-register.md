# Phase 2.0 — Owner decision register and contract baseline

- **Status:** In progress — consolidation and traceability of previously owner-approved architecture decisions. D2.0-01 explicitly records the existing approved dual HTTP/JSON + gRPC transport model. The remaining entries are not requests to decide these matters again; they identify where Community's abridged ADR carryover must be reconciled with the complete owner-approved baseline. An omission from a short public ADR is not evidence that the owner never decided it.
- **Scope:** Ferrum Vault Community only.
- **Parent:** [ROADMAP Phase 2](../../ROADMAP.md#phase-2-native-api-authentication-authorization-and-audit).
- **Purpose:** Consolidate and trace the existing owner-approved Phase 2 architecture into the public Community roadmap and ADRs. This register records binding decisions, operation coverage and precise traceability gaps. It is not a fresh decision questionnaire and must not reopen or replace prior owner approvals.

## 1. Decision-control rules

1. Existing owner-approved ADR requirements remain binding. Phase 2.0 must apply them, not reopen or silently weaken them.
2. The public ADRs in this repository are Community adaptations of an owner-approved source baseline, as explained in SOURCE-MAP.md. A missing detail in an abridged public adaptation is a documentation/provenance gap, not proof that no decision exists.
3. Preserve and trace prior owner-approved decisions. Do not ask the owner to select again, substitute a new option or change an existing value merely because a public summary is brief.
4. Only when the complete owner-approved baseline truly has no decision, or a genuine conflict exists, may a new owner decision be raised and recorded in a new/superseding ADR.
5. A feature must not be implemented with guessed parameters. Use the already approved value when it exists; if its authoritative value cannot yet be verified, pause only that dependent implementation until the source decision is reconciled.
6. Phase 2.0 consolidates the decisions and maps them to routes/contracts/tests. It does not authorize Phase 2.1–2.6 runtime implementation. Phase 0's explicit owner closeout gate remains visible in the roadmap until recorded.

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

## 3. Native operation family cross-reference — reconcile with approved catalog

This cross-reference is not a substitute for the full approved endpoint catalog. It identifies operation families already within the system design so they can be mapped to the previously approved exact routes, methods, schemas and response fields. Do not treat this short summary as a reason to re-decide their inclusion or exclusion.

| Area | Operation family to map to the existing approved API catalog | Existing dependency / boundary | Phase 2.0 status |
|---|---|---|---|
| Service diagnostics | Process liveness, readiness and non-secret service diagnostics | Server lifecycle and dependency health are not yet implemented | Copy approved inclusion and permitted fields from the source catalog |
| Seal state | Read current seal/bootstrap state | ferrum-seal library; response may reveal operational state | Copy approved route and sealed classification from the source catalog |
| Bootstrap | Initialize/bootstrap the root ceremony and persist its state | Existing Phase 1 seal/recovery contracts; durable service composition required | Copy approved operation and caller authority; preserve one-time semantics |
| Unseal | Submit the mandatory Shamir 2-of-3 unseal material | Unsealer port; shares are sensitive and must never enter logs, audit bodies or artifacts | Copy approved request contract and throttling policy; preserve Shamir 2-of-3 |
| Seal | Request a transition to Sealed | SealController boundary; mutation requires authorization and audit under approved rules | Copy approved operation and authority rules |
| Root lifecycle | Generate/rotate/revoke root operations | Existing 2-of-3 RootQuorumPolicy; sensitive root material handling must be specified | Copy approved root-operation surface and preserve independent 2-of-3 quorum |
| Authentication | Issue/inspect/renew/revoke credentials, if selected | Credential format, issuer and lifecycle are undecided | Copy approved authentication mechanism and operation subset |
| Identity administration | Create/disable/inspect identities, if selected | Trusted server-side principal model is undecided | Inclusion and authority pending |
| Policy administration | Create/read/update/delete/list ACL policies, if selected | Policy grammar, storage and administrative recovery are undecided | Copy approved identity operation set and authority |
| Audit administration | Verify audit-chain integrity and inspect non-secret sink status, if selected | Audit schema, verification and operational permissions are undecided | Copy approved exposure channel and permissions |

### Explicit Phase 2 exclusions

The following are not native Phase 2 operations and must not be represented as implemented or pulled into the endpoint catalog without a roadmap/ADR change:

- KV v2 and lease engine operations (Phase 4).
- PKI engine operations (Phase 3).
- Transit engine operations (Phase 5).
- Encrypted Raft/HA operations (Phase 6).
- CLI, UI and distribution/packaging workflows (their later roadmap phases).
- Vault API compatibility routes (later optional work under ADR-0018).

## 4. Route security-classification cross-reference

Apply the already approved route classifications to every selected operation. The labels below indicate fields that must be copied from the source catalog; they are not invitations to create new classifications or choose new defaults.

| Operation category | Available while sealed? | Authentication | Authorization | Required audit intent/outcome | Additional invariant |
|---|---|---|---|---|---|
| Liveness/readiness | Copy approved health/readiness exposure and fields | Pending | Pending | Pending | Must not disclose secrets, credentials, shares or protected values |
| Seal-state diagnostics | Copy approved sealed-state rule | Copy approved auth rule | Copy approved ACL rule | Copy approved audit rule | Preserve approved limits on state disclosure |
| Bootstrap | Copy approved bootstrap sealed-mode rule | Copy approved bootstrap authority | Pending | Sensitive lifecycle audit per approved contract | One-time/replay protection; never persist or log shares/tokens in plaintext |
| Unseal | Copy approved sealed-mode exposure | Mandatory Shamir 2-of-3; copy approved request/auth envelope | Copy approved authorization rule | Copy approved intent/outcome rule | Reject wrong, duplicate, mixed-ceremony or insufficient shares; no provider fallback |
| Seal | Copy approved sealed-state rule | Copy approved authentication rule | Copy approved authorization rule | Required for sensitive mutation per approved policy | Failure must not leave a partially transitioned state |
| Root lifecycle | Copy approved sealed-state rule | Separate 2-of-3 root-operation quorum remains mandatory | Copy approved authorization rule | Required for sensitive mutation | API auth must not replace or weaken the independent quorum |
| Credential/identity changes | Copy approved sealed-state rule | Copy approved authentication rule | Copy approved authorization rule | Required for security-sensitive changes | Secret credential material never appears in logs or audit payloads |
| ACL policy changes | Copy approved sealed-state rule | Copy approved authentication rule | Administrative policy is deny-by-default; copy approved admin roles | Required | Policy change/lockout recovery and atomicity must be defined |
| Audit verification/diagnostics | Copy approved sealed-state rule | Copy approved authentication rule | Copy approved audit permissions | Preserve approved non-recursive failure/recovery handling | Diagnostics must not expose protected audit contents or bypass sink-failure behavior |

## 5. Decision provenance and implementation traceability

These entries are **not a request to decide again**. They separate what the current public Community record explicitly proves from details that must be carried over from the complete, previously owner-approved architecture baseline. The owner-approved source decision remains authoritative; do not replace it with a candidate alternative. Where the public Community adaptation does not reproduce a detail, record the provenance link or adapt that existing decision into the Community ADR. Only a genuine gap in the original approved baseline can become a new decision.

### D2.0-01 — Native transports and shared request pipeline

- **Status:** **ALREADY APPROVED in the owner architecture baseline** by ADR-0005's HTTP/gRPC server requirement; this Community record explicitly confirms both native transports, with HTTP using JSON, and one shared authoritative security pipeline.
- **ADR:** [ADR-0025 — Dual native API transports with a shared security pipeline](../adr/0025-dual-api-transports-shared-security-pipeline.md).
- **Must preserve:** TLS 1.3 via rustls, the exact ADR-0005 pipeline order and equivalent security semantics across both transports.
- **Still open:** server/framework selection, listener topology, JSON schema/source-of-truth tooling, gRPC IDL/serialization tooling, cross-transport error mapping and operation-by-operation transport coverage.
- **Treatment:** consolidation/clarification of the prior decision, not a request to choose the transport again.

### D2.0-02 — Wire/schema and error contract

- **Already fixed:** native HTTP transport uses JSON and /v1; gRPC is also a native transport. API versioning is semantic with the two-minor deprecation policy (ADR-0015).
- **Traceability task:** carry over the previously owner-approved schema/IDL, serialization and error-mapping decisions from the authoritative design record into the Community API contract docs. Do not select a new schema or error design from the examples previously listed here.
- **Do not reopen:** protocol format or versioning choices already approved. Any details absent from the short Community ADR summary must first be reconciled against the approved source baseline.

### D2.0-03 — Native endpoint and operation catalog

- **Already fixed:** engine boundaries and roadmap ordering for PKI, KV v2/leases, Transit, HA, CLI, UI and optional Vault compatibility are defined by the approved roadmap/ADRs; those operations must not be pulled forward into the native Phase 2 MVP.
- **Traceability task:** consolidate the already approved Phase 2 system, seal, auth, policy and audit operations, routes/methods and explicit exclusions from the full owner-approved API design. Do not invent a smaller/different MVP list or ask for these decisions again.

### D2.0-04 — Authentication mechanism and credential representation

- **Already fixed:** the ordered authentication stage in ADR-0005; dynamically dispatched authentication extensions follow ADR-0002 async_trait + Send + Sync and its cancellation/lifetime/error/concurrency/security contract; trusted principal context is server-owned.
- **Traceability task:** carry over the previously approved authentication methods, credential format, credential storage/validation and bootstrap authority from the complete owner-approved design. Do not substitute AppRole/Vault compatibility, a new token type, passwords, mTLS identity or an external IdP merely because they appeared as examples in the earlier draft.

### D2.0-05 — Identity and credential lifecycle

- **Already fixed:** authentication must produce trusted server-side identity context; identity-based rate limiting follows authentication; client-supplied identity/tenant cannot override server context.
- **Traceability task:** reproduce the existing owner-approved principal schema, credential lifecycle and expiry/renewal/revocation/rotation/replay behavior in the Community contract docs. This register does not create new fields or lifetimes.

### D2.0-06 — ACL and canonical resource semantics

- **Already fixed:** canonical route/ACL evaluation occurs in the ADR-0005 pipeline; authorization is deny-by-default as specified in the approved Phase 2 roadmap; Community tenant is root and derived from trusted server context per ADR-0019.
- **Traceability task:** carry over the previously approved ACL grammar, capability vocabulary, matching/precedence and policy lifecycle from the complete design record. Do not replace the approved model with an alternative merely because the summary ADR does not repeat its syntax.

### D2.0-07 — Rate limits, trusted proxy and request bounds

- **Already fixed:** distinct IP-based pre-auth and identity-based post-auth rate-limit stages and request size/time bounds are mandatory in ADR-0005.
- **Traceability task:** import the previously approved algorithm, quotas/windows/bursts, limits, trusted-proxy semantics and scope. Do not propose new numeric values or algorithms until the complete approved decision source has been reconciled.

### D2.0-08 — Sealed-mode allowlist

- **Already fixed:** only a minimal, explicit allowlist of non-sensitive endpoints may remain available while Sealed (ADR-0005).
- **Traceability task:** reproduce the exact already approved endpoint/field allowlist and any authentication exceptions from the owner-approved service design. Do not silently broaden it or replace it with a newly suggested list.

### D2.0-09 — TLS certificate and trust lifecycle

- **Already fixed:** TLS 1.3 and rustls are mandatory (ADR-0005).
- **Traceability task:** carry over the existing owner-approved certificate provisioning, trust, rotation and reload requirements. The ADR-0005 summary does not enumerate those details; its brevity is not permission to choose a different lifecycle.

### D2.0-10 — Durable audit event, hash chain and sinks

- **Already fixed:** JSON-file hash-chain integrity plus stdout/syslog are the minimum destinations; retention is configurable with a 90-day default; intent must be durable before sensitive operations/disclosure and the result is recorded durably afterward; failure is fail-closed; local hash chains do not claim off-host immutability (ADR-0005).
- **Traceability task:** carry over the previously approved canonical event schema, hash/chain details, write durability and rotation/archive rules. Do not replace the approved algorithm or event contract with a new one.

### D2.0-11 — Audit/state coordination and service operations

- **Already fixed:** when audit and business state cannot share a transaction, use an outbox, idempotency and reconciliation (ADR-0005); Phase 1 redb atomic transaction contracts apply wherever their documented boundary covers the operation (ADR-0003); server distribution policy is in ADR-0022.
- **Traceability task:** reconcile existing approved decisions for the outbox schema/idempotency/recovery workflow, validated service configuration, health/readiness and graceful shutdown. Do not design a replacement from scratch or assume that a short public ADR contains the whole contract.

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

This table tracks the provenance of decisions the owner says were already approved. It is not a request to select again. Add the authoritative source ADR/section and the Community carryover reference for each item.

| Decision ID | Owner selection / explicit exclusion | Rationale and trade-offs | ADR reference | Approval date |
|---|---|---|---|---|
| D2.0-01 | HTTP/JSON + gRPC; one shared authoritative security pipeline | Two native access transports without duplicated/weaker security controls | [ADR-0025](../adr/0025-dual-api-transports-shared-security-pipeline.md) | 2026-11-15 |
| D2.0-02 | Previously owner-approved; carry over without re-selection | Preserve original rationale and behavior | Link existing source decision and Community ADR | Existing approval |
| D2.0-03 | Previously owner-approved; carry over without re-selection | Preserve original rationale and behavior | Link existing source decision and Community ADR | Existing approval |
| D2.0-04 | Previously owner-approved; carry over without re-selection | Preserve original rationale and behavior | Link existing source decision and Community ADR | Existing approval |
| D2.0-05 | Previously owner-approved; carry over without re-selection | Preserve original rationale and behavior | Link existing source decision and Community ADR | Existing approval |
| D2.0-06 | Previously owner-approved; carry over without re-selection | Preserve original rationale and behavior | Link existing source decision and Community ADR | Existing approval |
| D2.0-07 | Previously owner-approved; carry over without re-selection | Preserve original rationale and behavior | Link existing source decision and Community ADR | Existing approval |
| D2.0-08 | Previously owner-approved; carry over without re-selection | Preserve original rationale and behavior | Link existing source decision and Community ADR | Existing approval |
| D2.0-09 | Previously owner-approved; carry over without re-selection | Preserve original rationale and behavior | Link existing source decision and Community ADR | Existing approval |
| D2.0-10 | Previously owner-approved; carry over without re-selection | Preserve original rationale and behavior | Link existing source decision and Community ADR | Existing approval |
| D2.0-11 | Previously owner-approved; carry over without re-selection | Preserve original rationale and behavior | Link existing source decision and Community ADR | Existing approval |

## 10. Phase 2.0 completion checklist

- [ ] Owner approves the final native operation catalog and explicit exclusions.
- [ ] Every decision D2.0-01 through D2.0-11 is owner-approved or explicitly deferred with dependent feature disabled.
- [ ] Any change to an existing approved requirement has a new/superseding ADR; existing requirements are not silently weakened.
- [ ] Every selected operation has a completed seal/authentication/authorization/audit classification.
- [ ] Logical interface contracts and request-pipeline invariants map to concrete tests and responsible subphases.
- [ ] Threat-model changes, residual risks and operational dependencies are recorded.
- [ ] Roadmap and ADR index link to the approved records.
- [ ] Phase 0 owner closeout gate is recorded before Phase 2.1 runtime implementation begins.

**Current result:** the existing Phase 2 architecture is to be consolidated, not re-decided. The owner has clarified that D2.0-02 through D2.0-11 were already approved; their entries track source/carryover references rather than asking for new selections. Remaining work is to copy those approved specifics into the public Community records and map operations to tests. No Phase 2 runtime implementation is authorized before the Phase 0 entry gate and completion of this documentation reconciliation.
