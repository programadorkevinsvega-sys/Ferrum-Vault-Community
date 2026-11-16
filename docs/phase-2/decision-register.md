# Phase 2.0 — Approved design carryover and contract baseline

- **Status:** In progress — Phase 0 was explicitly accepted on 2026-11-16. Existing owner-approved Phase 2 architecture remains binding. On 2026-11-16 the owner explicitly delegated selection of missing low-level Community details to the technical architect; those new selections are now recorded in ADR-0026 through ADR-0029 and the machine-readable contracts. Phase 2.0 remains open for validation and owner acceptance.
- **Scope:** Ferrum Vault Community only.
- **Parent:** [ROADMAP Phase 2](../../ROADMAP.md#phase-2-native-api-authentication-authorization-and-audit).
- **Purpose:** Preserve all existing owner-approved architecture and separately identify new detailed defaults selected under the owner's explicit delegation. This register records the provenance class, technical contract, operation coverage, validation and acceptance gate for each decision. It is not a fresh questionnaire.

## 1. Decision-control rules

1. Existing owner-approved ADR requirements remain binding. Phase 2.0 must apply them, not reopen or silently weaken them.
2. The public ADRs in this repository are Community adaptations of an owner-approved source baseline, as explained in SOURCE-MAP.md. A missing detail in an abridged public adaptation is a documentation/provenance gap, not proof that no decision exists.
3. Preserve and trace prior owner-approved decisions. Do not ask the owner to select again, substitute a new option or change an existing value merely because a public summary is brief.
4. Where the owner-approved baseline leaves a low-level implementation detail unspecified, use the explicit delegation recorded on 2026-11-16: the technical architect selects a robust Community default and records it as a **delegated technical selection**, never as an earlier owner-approved choice. A true conflict with a higher-priority owner-approved ADR must be surfaced and resolved before implementation.
5. Do not silently guess or drift. Existing approved values are binding. Missing details are filled only by a documented delegated selection in ADR-0026–0029; if a selection conflicts with an approved ADR, the approved ADR prevails and the dependent implementation is blocked.
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
| Audit baseline | JSON file with hash-chain integrity plus stdout/syslog minimum; configurable 90-day default. Detailed event/chain/outbox behavior is selected in the delegated contract without weakening ADR-0005 | [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md); [ADR-0028](../adr/0028-phase-2-durable-audit-and-outbox.md) |
| Native API lifecycle | Native API is under /v1, uses semantic versioning and a two-minor-version deprecation policy | [ADR-0015](../adr/0015-reproducible-builds-and-api-versioning.md) |
| Dynamic extensions | Dynamically dispatched auth/audit/provider extensions use async traits with Send + Sync; document cancellation, lifetimes, errors, concurrency and security guarantees | [ADR-0002](../adr/0002-async-extension-contracts.md) |
| Storage | Protected values are encrypted before generic storage; initial Community backend is redb and the shared backend contract is linearizable | [ADR-0003](../adr/0003-storage-backend-contract.md) |
| Community tenant | Community remains single-tenant; logical tenant is root, derived from trusted authenticated/authorized server context. No client-selected tenant | [ADR-0019](../adr/0019-community-tenant-model.md) |
| Seal provider | Shamir 2-of-3 is the mandatory default Unsealer. AWS KMS is optional, feature-gated and disabled by default; no silent provider fallback | [ADR-0024](../adr/0024-unsealer-port-and-optional-aws-kms.md) |
| Compatibility surface | Optional Vault API subset is later, after the native API is stable and legal review is complete; it is not Phase 2's native API | [ADR-0018](../adr/0018-vault-api-compatibility-subset.md) |
| Administrative UI | MVP does not include a web UI; a later UI uses this same server/API and never replaces server-side controls | [ADR-0021](../adr/0021-user-interface.md) |
| Verification | Apply unit, property, fuzz, integration, failure-injection, concurrency where appropriate, Miri where applicable, negative-security, E2E, benchmark and interoperability evidence; target 90% measured coverage for crypto, seal, policy, auth and audit | [ADR-0010](../adr/0010-testing-and-security-evidence.md) |

## 3. Native operation catalog and phase boundary

The detailed native operation catalog is now defined in the [Phase 2 service contract](service-contract.md), [OpenAPI 3.2.1](openapi.yaml) and [proto3 IDL](../../proto/ferrum/v1/service.proto). The routes and RPC names are **new delegated technical selections recorded on 2026-11-16** in [ADR-0026](../adr/0026-phase-2-native-service-contracts.md); they are not represented as entries copied verbatim from the abbreviated source baseline.

The catalog covers health/readiness, seal status, bootstrap, Shamir unseal, seal, password and AppRole authentication, token lifecycle, password identity administration, AppRole administration, ACL policy administration, root-operation begin/approval/status and audit health. Each operation has a canonical operation/resource/action identifier, shared request context and mapped HTTP/gRPC errors.

### Explicit Phase 2 exclusions

The following remain outside this native Phase 2 catalog:

- PKI issuance/revocation (Phase 3).
- KV v2 and leases (Phase 4).
- Transit operations (Phase 5).
- Encrypted Raft/HA (Phase 6).
- Web UI (deferred under ADR-0021).
- Vault API compatibility routes (optional later work under ADR-0018, subject to stability and legal review).
- OIDC, Kubernetes auth and LDAP; the approved Phase 2 authentication MVP remains token, AppRole, mTLS and username/password with Argon2id.
- Enterprise-only APIs, code, packages, infrastructure or services.

## 4. Route security classification

The authoritative per-operation classification is in the security matrix within [service-contract.md](service-contract.md). It is part of the delegated technical selection recorded by ADR-0026 and is binding for implementation unless superseded through review.

### Exact sealed-mode allowlist

Only these six HTTP operations remain reachable while sealed:

| HTTP operation | Authentication while sealed | Permitted response/data |
|---|---|---|
| `GET /v1/sys/health/live` | None; pre-auth IP limit | Liveness only |
| `GET /v1/sys/health/ready` | None; pre-auth IP limit | Redacted readiness; no dependency secrets |
| `GET /v1/sys/seal-status` | None; pre-auth IP limit | `initialized`, `sealed`, threshold only |
| `POST /v1/sys/bootstrap/consume` | Valid one-time bootstrap token, only when uninitialized | One-time restricted setup token |
| `POST /v1/sys/unseal/sessions` | No bearer token; pre-auth IP limit | Volatile session ID, expiry and threshold |
| `POST /v1/sys/unseal/sessions/{sessionId}/shares` | One FRS1 share per distinct participant | Accepted/completed state only; never participant IDs or submitted share count |

No password/AppRole login, token, policy, audit-administration, root operation or protected business handler is exposed while sealed. All unknown/protected routes return the same generic sealed/unavailable class. The gRPC methods map to these same six operations and inherit the same sealed-mode rules.

### Shared security requirements

- Every other route requires the authentication method and canonical ACL action specified by the service contract.
- Deny-by-default remains mandatory. Missing/corrupt/unavailable policy denies; explicit deny overrides allow.
- Sensitive mutations and protected reads require durable audit intent before side effects or disclosure, plus a durable outcome according to ADR-0005/0028.
- Unseal uses the mandatory Shamir 2-of-3 Unsealer. `generate-root`, root rotation and revocation additionally require the independent configured root-operation 2-of-3 quorum under ADR-0014; API authentication never replaces the quorum.
- The owner-approved ADR-0005 request-pipeline order is unchanged across HTTP/JSON and gRPC. These are classifications and defaults, not a weaker per-route pipeline.

## 5. Decision provenance and implementation traceability

Decisions are explicitly separated into two classes. **D2.0-01 through D2.0-13** preserve previously owner-approved choices and requirements; they must not be re-selected. **D2.0-14 through D2.0-17** record new detailed Community defaults selected under the owner's explicit delegation on 2026-11-16. The latter are not falsely attributed to the old source baseline and remain subject to the Phase 2.0 acceptance gate.

### D2.0-01 — Native transports and shared request pipeline

- **Status:** OWNER-APPROVED, 2026-11-15 clarification. HTTP/JSON and gRPC both use one authoritative security pipeline.
- **ADR:** [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md), [ADR-0025](../adr/0025-dual-api-transports-shared-security-pipeline.md).
- **Must preserve:** TLS 1.3/rustls, server-generated request IDs, exact ADR-0005 ten-stage order and equivalent security semantics.

### D2.0-02 — Wire/schema and error contract

- **Existing approved constraints:** HTTP/JSON under `/v1`; gRPC as the second native transport; semantic versioning and two-minor deprecation policy.
- **Delegated completion:** OpenAPI 3.2.1, proto3 package `ferrum.v1`, canonical operation mapping and equivalent RFC 9457 / canonical gRPC errors are defined by [ADR-0026](../adr/0026-phase-2-native-service-contracts.md), [openapi.yaml](openapi.yaml) and [service.proto](../../proto/ferrum/v1/service.proto).

### D2.0-03 — Native endpoint and operation catalog

- **Existing approved boundary:** system/seal/bootstrap/root/auth/identity/ACL/audit service; PKI, KV v2/leases, Transit, encrypted Raft/HA and web UI excluded; optional Vault compatibility remains later under ADR-0018.
- **Delegated completion:** exact HTTP paths, methods, gRPC service/method names and operation IDs are fixed in [service-contract.md](service-contract.md), [openapi.yaml](openapi.yaml) and [service.proto](../../proto/ferrum/v1/service.proto), ADR-0026.

### D2.0-04 — Authentication mechanism and credential representation

- **Existing approved methods:** token, AppRole, mTLS client certificate, username/password with Argon2id; OIDC, Kubernetes auth and LDAP deferred.
- **Delegated completion:** opaque 256-bit revocable tokens; Argon2id parameters and bounded concurrency; AppRole Secret ID TTL/use bounds; exact mTLS URI SAN mapping and revocation behavior; see [service-contract.md](service-contract.md) and ADR-0027.

### D2.0-05 — Identity and credential lifecycle

- **Existing approved constraints:** server-owned principal; one-time bootstrap; expiry, revocation and replay protection; no caller-controlled principal or tenant.
- **Delegated completion:** bootstrap/token TTLs, secret-once responses, token rotation on renewal, parent-child revocation, no orphan-token feature, bounded identity data and generic authentication failure responses are defined by ADR-0027 and the service contract.

### D2.0-06 — ACL and canonical resource semantics

- **Existing approved constraints:** canonical route/action, deny-by-default, least privilege and Community tenant `root` from trusted server context.
- **Delegated completion:** versioned JSON ACL schema; fixed seven-action vocabulary; literal/`*`/terminal-`**` resource grammar; deny-overrides; immutable per-request policy snapshot; CAS revisions; canonicalization rejection rules. See ADR-0027 and service-contract.md.

### D2.0-07 — Rate limits, trusted proxy and request bounds

- **Existing approved constraints:** pre-auth IP and post-auth identity controls, request size/time limits, quotas, concurrency and backpressure.
- **Delegated completion:** conservative hard caps and defaults are in service-contract.md and configuration-contract.md, including trusted socket peer by default, explicit proxy CIDRs, bounded RFC 7239 Forwarded chain, no X-Forwarded-For authority, no silent rate-limit disable on backend failure. See ADR-0027.

### D2.0-08 — Sealed-mode allowlist

- **Existing approved constraint:** only a minimal explicit allowlist of non-sensitive operations remains available while sealed (ADR-0005).
- **Delegated completion:** exactly six HTTP operations and corresponding gRPC operations are listed in Section 4 and service-contract.md. No login, token, policy, audit-admin or root operation is exposed while sealed.

### D2.0-09 — TLS certificate and trust lifecycle

- **Existing approved constraint:** TLS 1.3 with rustls; no plaintext downgrade.
- **Delegated completion:** one listener, ALPN, TLS 1.3 only/no 0-RTT, distinct server/client trust, exact mTLS SAN mapping, CRL fail-closed behavior, atomic certificate/trust reload, strict file permissions and proxy trust behavior. See ADR-0029 and configuration-contract.md.

### D2.0-10 — Durable audit event, hash chain and sinks

- **Existing approved constraints:** JSON hash-chain file plus stdout/syslog minimum, configurable 90-day default, durable intent/outcome, fail closed and no claim of off-host immutability (ADR-0005).
- **Delegated completion:** allowlisted event schema; RFC 8785 canonicalization; versioned SHA-256 domain-separated chain; append/fsync guarantees; chain-preserving rotation/checkpoint; TLS syslog only; no secret-bearing fields. See ADR-0028 and service-contract.md.

### D2.0-11 — Audit/state coordination and service operations

- **Existing approved constraints:** use outbox, idempotency and reconciliation whenever audit and state do not share a transaction; accepted redb transaction semantics remain bounded by ADR-0003.
- **Delegated completion:** 128-bit idempotency keys with 24-hour scope, atomic outbox/state where possible, bounded retries, 10,000/60-second pending thresholds, startup reconciliation and indeterminate state when outcome cannot be proven. Strict TOML configuration and bounded graceful shutdown are defined in ADR-0028/0029.

### D2.0-12 — Clock and time semantics

- **Existing approved constraints:** monotonic clock for durations; wall clock for certificate validity (ADR-0014).
- **Delegated completion:** a backward wall-clock jump greater than 30 seconds enters `clock_unsafe`; no issuance/renewal or mTLS auth until time is repaired and explicitly acknowledged locally. See service-contract.md and configuration-contract.md. KV/lease engine semantics remain Phase 4.

### D2.0-13 — CLI distribution scope

- **Status:** OWNER-APPROVED. Phase 2 CLI archives cover Linux x86_64/aarch64, universal macOS and Windows x86_64; checksums/signatures; crates.io only after separate owner approval. Preserve ADR-0023; do not expand packaging scope here.

### D2.0-14 — Native service and wire contract (delegated)

- **Status:** DELEGATED TECHNICAL SELECTION, 2026-11-16. OpenAPI 3.2.1 is the HTTP contract; proto3 `ferrum.v1` is the gRPC contract; shared canonical operations and error mapping are binding.
- **ADR/artifacts:** ADR-0026, service-contract.md, openapi.yaml and proto/ferrum/v1/service.proto.

### D2.0-15 — Authentication, ACL and resource-control detail (delegated)

- **Status:** DELEGATED TECHNICAL SELECTION, 2026-11-16. Opaque revocable tokens; specified Argon2id/AppRole/mTLS/bootstrap parameters; small versioned ACL language; deny-overrides; explicit request/resource caps and mandatory rate limits.
- **ADR/artifacts:** ADR-0027, service-contract.md and configuration-contract.md.

### D2.0-16 — Durable audit/outbox/idempotency detail (delegated)

- **Status:** DELEGATED TECHNICAL SELECTION, 2026-11-16. Deterministic allowlisted events; RFC 8785 canonicalization; versioned SHA-256 hash chain; fsync-before-effect/disclosure; outbox/idempotency/reconciliation with bounded backpressure.
- **ADR/artifacts:** ADR-0028 and service-contract.md.

### D2.0-17 — TLS, configuration and process lifecycle detail (delegated)

- **Status:** DELEGATED TECHNICAL SELECTION, 2026-11-16. Single TLS listener; TLS 1.3/rustls/no 0-RTT; strict TOML; safe file permissions; limited atomic trust-bundle reload; bounded graceful shutdown.
- **ADR/artifacts:** ADR-0029, configuration-contract.md and ferrum.phase2.example.toml.

## 6. Logical interface and contract boundaries

The exact wire contracts are defined in OpenAPI 3.2.1 and proto3. The table below describes the internal responsibilities that must preserve those externally observable contracts; Rust type names and crate boundaries remain implementation details.

| Boundary | Contract responsibilities | Required failure behavior |
|---|---|---|
| Listener/transport | TLS 1.3/rustls, selected protocol(s), peer identity, connection lifecycle, cancellation | Reject invalid TLS and malformed transport input; no plaintext downgrade |
| Request context | Server request ID, trusted peer address, deadline/size budget, seal state, authenticated principal when available, canonical resource/action, tenant root | Context is server-owned; never accept client-provided principal/tenant as authoritative |
| API handler | Versioned operation contract, input validation, typed errors | Cannot bypass pipeline or return protected data before authorization/audit gates |
| Authentication | Credential validation and trusted principal creation; dynamic extension contract per ADR-0002 | Invalid, expired, revoked, replayed, unavailable or indeterminate auth fails closed |
| Rate limiter | Pre-auth source and post-auth identity controls; exact limits in ADR-0027/configuration contract | Backend/state failure fails closed; never silently disable limits |
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
| D2.0-02 | HTTP/JSON + gRPC wire/schema and error behavior; `/v1`, semver, two-minor deprecation | Stable, versioned native API with equivalent cross-transport semantics | [ADR-0015](../adr/0015-reproducible-builds-and-api-versioning.md); [ADR-0025](../adr/0025-dual-api-transports-shared-security-pipeline.md) | Existing approval (source baseline) |
| D2.0-03 | Phase 2 native service, seal/bootstrap/root, auth, identity, ACL and audit operations; later engines and Vault compatibility excluded from native Phase 2 | Maintain phase boundaries and keep native Community API distinct from optional compatibility | [ROADMAP Phase 2](../../ROADMAP.md#phase-2-native-api-authentication-authorization-and-audit); [ADR-0018](../adr/0018-vault-api-compatibility-subset.md); [ADR-0021](../adr/0021-user-interface.md) | Existing approval (source baseline) |
| D2.0-04 | Token, AppRole, mTLS client certificate, username/password with Argon2id; OIDC, Kubernetes auth and LDAP deferred | Approved MVP methods with constrained extension and explicit deferred integrations | [ADR-0002](../adr/0002-async-extension-contracts.md); [ADR-0014](../adr/0014-root-ceremony-recovery-and-backups.md); [ROADMAP Phase 2](../../ROADMAP.md#phase-2-native-api-authentication-authorization-and-audit) | Existing approval (source baseline) |
| D2.0-05 | Server-owned principal; one-time bootstrap token; approved expiry, renewal, revocation and replay protections | Prevent caller-controlled identity and credential reuse | [ADR-0002](../adr/0002-async-extension-contracts.md); [ADR-0014](../adr/0014-root-ceremony-recovery-and-backups.md); [ADR-0019](../adr/0019-community-tenant-model.md) | Existing approval (source baseline) |
| D2.0-06 | Canonical route/action ACL, deny-by-default and least privilege; Community tenant `root` from trusted server context | Prevent route ambiguity, implicit allow and tenant spoofing | [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md); [ADR-0019](../adr/0019-community-tenant-model.md); [ROADMAP Phase 2](../../ROADMAP.md#phase-2-native-api-authentication-authorization-and-audit) | Existing approval (source baseline) |
| D2.0-07 | Pre-auth IP and post-auth identity rate limits; request size/time bounds, quotas and backpressure | Bound unauthenticated and authenticated resource consumption | [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md); [ROADMAP Phase 2](../../ROADMAP.md#phase-2-native-api-authentication-authorization-and-audit) | Existing approval (source baseline) |
| D2.0-08 | Minimal explicit allowlist of non-sensitive endpoints while sealed | Expose only required safe diagnostics/lifecycle surface when sealed | [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md) | Existing approval (source baseline) |
| D2.0-09 | TLS 1.3 and rustls listener with approved certificate/trust lifecycle | Protect transport authenticity and confidentiality without weakening transport policy | [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md) | Existing approval (source baseline) |
| D2.0-10 | JSON hash-chain file plus stdout/syslog; 90-day configurable default; durable intent/outcome; fail-closed | Provide attributable, tamper-evident audit and block unrecorded sensitive actions | [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md) | Existing approval (source baseline) |
| D2.0-11 | Previously owner-approved; carry over without re-selection | Preserve original rationale and behavior | [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md); [ADR-0003](../adr/0003-storage-backend-contract.md); [ADR-0022](../adr/0022-server-distribution.md) | Existing approval |
| D2.0-12 | Monotonic durations; wall-clock certificate validity; approved drift/NTP behavior | Correct elapsed-time and certificate-validity semantics | [ADR-0014](../adr/0014-root-ceremony-recovery-and-backups.md) | Existing approval |
| D2.0-13 | Phase 2 CLI archive distribution targets | Support the approved CLI platforms and verifiable releases | [ADR-0023](../adr/0023-cli-distribution.md) | Existing approval |

## 10. Phase 2.0 completion checklist

- [x] The Community Phase 2 operation catalog, route names, methods, schemas and explicit exclusions are recorded in service-contract.md, OpenAPI and proto3 under delegated ADR-0026. Validation remains required.
- [ ] Every original owner-approved Phase 2 decision has provenance and a corresponding Community ADR/contract reference; no decision is reopened or replaced.
- [ ] Each operation has its previously approved sealed-mode, authentication, authorization, rate-limit and audit classification mapped to the responsible subphase.
- [x] HTTP/JSON and gRPC have versioned machine-readable contracts and shared error/operation semantics; automated compatibility and cross-transport runtime tests remain required.
- [ ] The approved token, AppRole, mTLS and Argon2id-password MVP method set is explicit; OIDC, Kubernetes auth and LDAP remain deferred.
- [ ] The monotonic-duration/wall-clock-certificate time model and Phase 2 CLI archive distribution under ADR-0023 are recorded.
- [x] Delegated ADR-0027/0028/0029 and service/configuration contracts now fix identity/credential, ACL, limits, TLS lifecycle, audit schema/durability and outbox recovery defaults; implementation tests remain outstanding.
- [ ] Threat-model changes, residual risks and tests are mapped to the responsible implementation subphases.
- [ ] ROADMAP, ADR index, architecture overview and security docs are consistent.
- [x] Phase 0 owner acceptance recorded on 2026-11-16; the Phase 0 entry gate is satisfied before Phase 2.1 runtime implementation.

**Current result:** Phase 0 is accepted. Existing owner-approved Phase 2 architecture has been preserved without re-selection. Under the owner's explicit 2026-11-16 delegation, the missing detailed Community choices are now selected and documented in ADR-0026–0029 and the service/OpenAPI/proto/configuration contracts. This is a delegated technical design, not evidence that these low-level values were present in the old source snapshot. Phase 2.0 remains open for machine-readable contract lint/compatibility checks, documentation/link consistency, exact-head CI/Gitleaks and owner acceptance. No Phase 2 runtime implementation is authorized until that gate is completed and accepted.
