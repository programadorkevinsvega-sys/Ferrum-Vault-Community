# Phase 2.0 — Approved design carryover and contract baseline

- **Status:** In progress — Phase 0 was explicitly accepted by the owner on 2026-11-16; Phase 2.0 is reconciling the already owner-approved Community architecture into complete public contracts. D2.0-01 records the approved dual HTTP/JSON + gRPC transport model. The remaining entries are carryover/provenance tasks, not requests to decide again. An omission from a short public ADR is not evidence that the owner never decided it.
- **Scope:** Ferrum Vault Community only.
- **Parent:** [ROADMAP Phase 2](../../ROADMAP.md#phase-2-native-api-authentication-authorization-and-audit).
- **Purpose:** Consolidate and trace the existing owner-approved Phase 2 architecture into the public Community roadmap and ADRs. This register records binding decisions, operation coverage and precise traceability gaps. It is not a fresh decision questionnaire and must not reopen or replace prior owner approvals.

## 1. Decision-control rules

1. Existing owner-approved ADR requirements remain binding. Phase 2.0 must apply them, not reopen or silently weaken them.
2. The public ADRs in this repository are Community adaptations of an owner-approved source baseline, as explained in SOURCE-MAP.md. A missing detail in an abridged public adaptation is a documentation/provenance gap, not proof that no decision exists.
3. Preserve and trace prior owner-approved decisions. Do not ask the owner to select again, substitute a new option or change an existing value merely because a public summary is brief.
4. Only when the complete owner-approved baseline truly has no decision, or a genuine conflict exists, may a new owner decision be raised and recorded in a new/superseding ADR.
5. A feature must not be implemented with guessed parameters. Use the already approved value when it exists; if its authoritative value cannot yet be verified, pause only that dependent implementation until the source decision is reconciled.
6. Phase 0 was explicitly accepted by the owner on 2026-11-16; its entry gate is satisfied. Phase 2.0 must still complete the design carryover and map it to contracts/tests before Phase 2.1–2.6 runtime implementation is authorized.

## 2. Binding constraints inherited from approved ADRs

| Constraint | Binding requirement | Source |
|---|---|---|
| Native transports | Expose both HTTP/JSON and gRPC; transport adapters share one authoritative security pipeline and equivalent security semantics | [ADR-0025](../adr/0025-dual-api-transports-shared-security-pipeline.md) |
| Request pipeline | Preserve the approved order: TLS 1.3 listener using rustls; HTTP/gRPC server and request ID; request size/time limits; IP pre-auth rate limit; local seal check; authentication; identity rate limit; canonical route/ACL; handler; durable audit before/after sensitive operations | [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md) |
| Authentication MVP | Token, AppRole, mTLS client certificate, and username/password with Argon2id; OIDC, Kubernetes auth and LDAP are deferred | Owner-approved Phase 2 baseline; [ADR-0002](../adr/0002-async-extension-contracts.md) |
| Clock semantics | Monotonic clock for durations; wall clock for certificate validity; clock-drift tolerance and NTP alert behavior must be defined/tested in the relevant phase | [ADR-0014](../adr/0014-root-ceremony-recovery-and-backups.md) |
| CLI distribution | Phase 2 tar.gz/zip for Linux x86_64/aarch64, universal macOS and Windows x86_64; checksums/signatures; crates.io requires separate approval | [ADR-0023](../adr/0023-cli-distribution.md) |
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

This cross-reference identifies the Phase 2 operation families in the owner-approved Community scope. The source baseline confirms the families and phase boundaries, but the pinned public carryover does not itself reproduce every exact route, method, schema or response field. Those values must be transcribed from their existing owner-approved records; do not invent replacements or ask the owner to select again. See [approved-design-carryover.md](approved-design-carryover.md).

| Area | Operation family to map to the existing approved API catalog | Existing dependency / boundary | Phase 2.0 status |
|---|---|---|---|
| Service diagnostics | Process liveness, readiness and non-secret service diagnostics | Server lifecycle and dependency health are Phase 2 service composition | Carry over approved routes and permitted fields from the source catalog |
| Seal state | Read current seal/bootstrap state | ferrum-seal library; response may reveal operational state | Copy approved route and sealed classification from the source catalog |
| Bootstrap | Initialize/bootstrap the root ceremony and persist its state | Existing Phase 1 seal/recovery contracts; durable service composition required | Copy approved operation and caller authority; preserve one-time semantics |
| Unseal | Submit the mandatory Shamir 2-of-3 unseal material | Unsealer port; shares are sensitive and must never enter logs, audit bodies or artifacts | Copy approved request contract and throttling policy; preserve Shamir 2-of-3 |
| Seal | Request a transition to Sealed | SealController boundary; mutation requires authorization and audit under approved rules | Copy approved operation and authority rules |
| Root lifecycle | Generate/rotate/revoke root operations | Existing 2-of-3 RootQuorumPolicy; sensitive root material handling must be specified | Copy approved root-operation surface and preserve independent 2-of-3 quorum |
| Authentication | Token, AppRole, mTLS client certificate, and username/password with Argon2id; OIDC, Kubernetes auth and LDAP deferred | Trusted server-side principal; dynamic adapters follow ADR-0002 | Carry over the approved per-method sealed/auth/ACL/audit rules and exact routes |
| Identity administration | The approved identity-administration operations | Server-side principal context from the approved identity model | Copy approved identity operations and authority rules from the source catalog |
| Policy administration | The approved ACL/policy-administration operations | The owner-approved ACL grammar, storage and administrative recovery model | Copy approved policy operation set and authority from the source catalog |
| Audit administration | The approved audit verification and operational diagnostics | Audit schema, verification and operational permissions as already approved in the source design | Copy approved exposure channel and permissions |

### Explicit Phase 2 exclusions

The following are not native Phase 2 operations and must not be represented as implemented or pulled into the endpoint catalog without a roadmap/ADR change:

- KV v2 and lease engine operations (Phase 4).
- PKI engine operations (Phase 3).
- Transit engine operations (Phase 5).
- Encrypted Raft/HA operations (Phase 6).
- CLI, UI and distribution/packaging workflows (their later roadmap phases).
- Vault API compatibility routes (later optional work under ADR-0018).

## 4. Route security-classification cross-reference

Apply the already approved route classifications to every selected operation. The table records invariants that are explicit in ADRs; fields marked for carryover are traceability gaps, not new owner decisions. Copy the previously approved exact route classification; do not create defaults.

| Operation category | Available while sealed? | Authentication | Authorization | Required audit intent/outcome | Additional invariant |
|---|---|---|---|---|---|
| Liveness/readiness | Copy approved health/readiness exposure and fields | Copy approved authentication rule | Copy approved authorization rule | Copy approved audit rule | Must not disclose secrets, credentials, shares or protected values |
| Seal-state diagnostics | Copy approved sealed-state rule | Copy approved auth rule | Copy approved ACL rule | Copy approved audit rule | Preserve approved limits on state disclosure |
| Bootstrap | Copy approved bootstrap sealed-mode rule | Copy approved bootstrap authority | Copy approved authorization rule | Sensitive lifecycle audit per approved contract | One-time/replay protection; never persist or log shares/tokens in plaintext |
| Unseal | Copy approved sealed-mode exposure | Mandatory Shamir 2-of-3; copy approved request/auth envelope | Copy approved authorization rule | Copy approved intent/outcome rule | Reject wrong, duplicate, mixed-ceremony or insufficient shares; no provider fallback |
| Seal | Copy approved sealed-state rule | Copy approved authentication rule | Copy approved authorization rule | Required for sensitive mutation per approved policy | Failure must not leave a partially transitioned state |
| Root lifecycle | Copy approved sealed-state rule | Separate 2-of-3 root-operation quorum remains mandatory | Copy approved authorization rule | Required for sensitive mutation | API auth must not replace or weaken the independent quorum |
| Credential/identity changes | Copy approved sealed-state rule | Copy approved authentication rule | Copy approved authorization rule | Required for security-sensitive changes | Secret credential material never appears in logs or audit payloads |
| ACL policy changes | Copy approved sealed-state rule | Copy approved authentication rule | Administrative policy is deny-by-default; copy approved admin roles | Required | Policy change/lockout recovery and atomicity must be defined |
| Audit verification/diagnostics | Copy approved sealed-state rule | Copy approved authentication rule | Copy approved audit permissions | Preserve approved non-recursive failure/recovery handling | Diagnostics must not expose protected audit contents or bypass sink-failure behavior |

## 5. Decision provenance and implementation traceability

These entries are **not a request to decide again**. They separate what the current public Community record explicitly proves from details that must be carried over from the complete, previously owner-approved architecture baseline. The owner-approved source decision remains authoritative; do not replace it with a candidate alternative. Where the public Community adaptation does not reproduce a detail, record the provenance link or adapt that existing decision into the Community ADR. Only a genuine gap in the original approved baseline can become a new decision.

### D2.0-01 — Native transports and shared request pipeline

- **Status:** ALREADY APPROVED. Community Phase 2 includes HTTP with JSON and gRPC; both use one shared authoritative security pipeline.
- **ADR:** [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md) and [ADR-0025](../adr/0025-dual-api-transports-shared-security-pipeline.md).
- **Must preserve:** TLS 1.3/rustls, server-generated request IDs, and the exact ten-stage ADR-0005 order with equivalent security semantics over both transports.
- **Carryover traceability:** the exact server/framework, listener topology, schema/IDL, serialization and error mapping must be copied from the already approved owner records. The pinned abbreviated source snapshot does not reproduce those values; do not infer or replace them.
- **Treatment:** no transport re-selection or new option request.

### D2.0-02 — Wire/schema and error contract

- **Already fixed:** HTTP uses JSON under `/v1`; gRPC is the second native transport; API versioning is semantic with the two-minor deprecation policy (ADR-0015).
- **Traceability task:** transcribe the already owner-approved schema/IDL, serialization and cross-transport error mapping into the Community contract. The pinned source snapshot in SOURCE-MAP does not contain those exact values; this is a source-reference gap, not a new design question.
- **Do not reopen:** transport or versioning choices. Do not substitute a new schema/error design.

### D2.0-03 — Native endpoint and operation catalog

- **Already fixed:** Phase 2 includes the native service/API, authentication, policy/ACL, audit, bootstrap and root-operation integration. PKI (Phase 3), KV v2/leases (Phase 4), Transit (Phase 5), encrypted Raft/HA (Phase 6) and web UI are not Phase 2 native operations. Vault API compatibility is optional/later under ADR-0018. CLI distribution archives start in Phase 2 under ADR-0023.
- **Traceability task:** map the complete approved Phase 2 system, seal, authentication, identity, policy and audit operation set to exact routes/methods. The pinned source snapshot gives operation families rather than an exact route catalog; recover the owner-approved catalog and transcribe it verbatim. Do not invent a smaller/different MVP list or ask for decisions again.

### D2.0-04 — Authentication mechanism and credential representation

- **Already fixed:** MVP methods are token, AppRole, mTLS client certificate, and username/password with Argon2id. OIDC, Kubernetes authentication and LDAP are deferred. The ordered authentication stage comes after the seal gate; dynamic authentication extensions follow ADR-0002; trusted principal context is server-owned.
- **Traceability task:** transcribe the already approved per-method credential representation, storage/validation, issuer/bootstrap authority and exact lifecycle values from their owner-approved records. The public source snapshot confirms the method set but not every low-level representation; do not introduce an alternative.

### D2.0-05 — Identity and credential lifecycle

- **Already fixed:** authentication produces trusted server-side identity context; identity-based rate limiting follows authentication; client-supplied identity/tenant cannot override context. Bootstrap token is one-time, and the design requires expiry, revocation and replay protection.
- **Traceability task:** reproduce the already approved principal schema, all per-method credential lifecycle values, renewal/rotation/replay behavior and identity fields. Do not invent new fields or lifetimes.

### D2.0-06 — ACL and canonical resource semantics

- **Already fixed:** canonical route/ACL evaluation occurs in the ADR-0005 pipeline; authorization is deny-by-default and least-privilege over canonical paths/resources and capabilities; Community tenant is `root`, derived from trusted server context per ADR-0019.
- **Traceability task:** carry over the previously approved ACL grammar, capability vocabulary, matching/precedence, policy lifecycle and administrative recovery rules. Do not replace the approved model or invent policy syntax.

### D2.0-07 — Rate limits, trusted proxy and request bounds

- **Already fixed:** IP-based pre-auth and identity-based post-auth rate limits and request size/time bounds are mandatory in ADR-0005; the Phase 2 contract also includes quotas, concurrency and backpressure.
- **Traceability task:** transcribe the already approved algorithms, quotas/windows/bursts, request limits and trusted-proxy semantics. Numeric values are not guessed from defaults or common practice.

### D2.0-08 — Sealed-mode allowlist

- **Already fixed:** only a minimal, explicit allowlist of non-sensitive endpoints may remain available while Sealed (ADR-0005).
- **Traceability task:** reproduce the exact approved endpoint/response-field allowlist and any approved authentication exceptions. The pinned public source snapshot states the invariant but does not enumerate the routes; do not silently broaden it or invent a replacement list.

### D2.0-09 — TLS certificate and trust lifecycle

- **Already fixed:** TLS 1.3 with rustls is mandatory (ADR-0005).
- **Traceability task:** carry over the owner-approved certificate/key provisioning, trust roots, rotation and reload lifecycle. The pinned public source snapshot does not enumerate those values; do not choose an alternative lifecycle.

### D2.0-10 — Durable audit event, hash chain and sinks

- **Already fixed:** JSON-file hash-chain integrity plus stdout/syslog are the minimum destinations; retention is configurable with a 90-day default; intent must be durable before sensitive operations/disclosure and the result is recorded durably afterward; failure is fail-closed; local hash chains do not claim off-host immutability (ADR-0005).
- **Traceability task:** carry over the approved canonical event schema, hash/chain parameters, append durability and rotation/archive rules. The public baseline explicitly defers advanced export/archive details; preserve that boundary and do not substitute a new algorithm.

### D2.0-11 — Audit/state coordination and service operations

- **Already fixed:** when audit and business state cannot share a transaction, use an outbox, idempotency and reconciliation (ADR-0005); accepted redb atomic transaction contracts apply within their documented boundary (ADR-0003); server distribution policy is in ADR-0022.
- **Traceability task:** transcribe the approved outbox schema/idempotency key/recovery transitions, validated service configuration, health/readiness fields and graceful-shutdown contract. Do not design a replacement or infer operational defaults.

### D2.0-12 — Clock and time semantics

- **Already fixed:** durations use a monotonic clock; certificate validity uses wall-clock time (ADR-0014).
- **Traceability task:** carry over the approved clock-drift tolerance, rollback/jump handling and NTP alert behavior for the relevant service operations. KV/lease engine operations remain Phase 4; do not pull them into Phase 2.

### D2.0-13 — CLI distribution scope

- **Already fixed:** CLI distribution starts in Phase 2 with tar.gz/zip for Linux x86_64/aarch64, universal macOS and Windows x86_64; releases provide checksums and signatures, and crates.io requires separate owner approval (ADR-0023).
- **Treatment:** preserve this Phase 2 distribution scope; web UI and additional CLI channels remain deferred as stated in ADR-0021/0023.

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
| D2.0-11 | Previously owner-approved; carry over without re-selection | Preserve original rationale and behavior | [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md); [ADR-0003](../adr/0003-storage-backend-contract.md); [ADR-0022](../adr/0022-server-distribution.md) | Existing approval |
| D2.0-12 | Monotonic durations; wall-clock certificate validity; approved drift/NTP behavior | Correct elapsed-time and certificate-validity semantics | [ADR-0014](../adr/0014-root-ceremony-recovery-and-backups.md) | Existing approval |
| D2.0-13 | Phase 2 CLI archive distribution targets | Support the approved CLI platforms and verifiable releases | [ADR-0023](../adr/0023-cli-distribution.md) | Existing approval |

## 10. Phase 2.0 completion checklist

- [ ] The full owner-approved Phase 2 operation catalog, route names, methods, schemas and explicit exclusions are reproduced in Community documentation.
- [ ] Every original owner-approved Phase 2 decision has provenance and a corresponding Community ADR/contract reference; no decision is reopened or replaced.
- [ ] Each operation has its previously approved sealed-mode, authentication, authorization, rate-limit and audit classification mapped to the responsible subphase.
- [ ] HTTP/JSON and gRPC reference the previously approved wire/schema, IDL and error mapping; both exercise the same operation/security behavior.
- [ ] The approved token, AppRole, mTLS and Argon2id-password MVP method set is explicit; OIDC, Kubernetes auth and LDAP remain deferred.
- [ ] The monotonic-duration/wall-clock-certificate time model and Phase 2 CLI archive distribution under ADR-0023 are recorded.
- [ ] The approved identity/credential lifecycle, ACL grammar, limits, TLS certificate lifecycle, audit schema/durability and outbox recovery rules are transcribed without changes.
- [ ] Threat-model changes, residual risks and tests are mapped to the responsible implementation subphases.
- [ ] ROADMAP, ADR index, architecture overview and security docs are consistent.
- [x] Phase 0 owner acceptance recorded on 2026-11-16; the Phase 0 entry gate is satisfied before Phase 2.1 runtime implementation.

**Current result:** Phase 0 has been accepted by the owner. The existing Phase 2 architecture is to be consolidated, not re-decided. The owner has clarified that the Phase 2 decisions were already approved; entries track source/carryover references rather than ask for new selections. The confirmed Community scope is now recorded in [approved-design-carryover.md](approved-design-carryover.md). Remaining Phase 2.0 work is to transcribe the exact route/schema/security/configuration values from the complete owner-approved records, finish the route-level classification and test map, and align all public documents. No Phase 2 runtime implementation is authorized until Phase 2.0 itself is completed and accepted.
