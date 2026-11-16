# Phase 2 — Approved Community design carryover

- **Status:** Owner-approved architecture carryover; Phase 2.0 documentation reconciliation is in progress.
- **Scope:** Ferrum Vault Community only.
- **Purpose:** Consolidate the Community-applicable choices already approved by the owner. This is not a new ADR, a request to select alternatives, or authorization to start Phase 2 runtime implementation.
- **Source baseline:** The owner-approved architecture baseline identified in [SOURCE-MAP.md](../adr/SOURCE-MAP.md), commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`, together with the subsequent Community clarifications recorded in ADR-0014, ADR-0024 and ADR-0025.
- **Phase gate:** Phase 0 was explicitly accepted by the owner on 2026-11-16. Phase 2.0 must still complete before Phase 2.1 runtime implementation begins.

## 1. Native transports and API lifecycle

The Phase 2 Community MVP exposes both approved native transports:

1. HTTP with JSON request/response representations under `/v1`.
2. gRPC as a second native transport.

Both enter the same authoritative security pipeline and share request identity, principal, tenant, seal-state, rate-limit, authorization and audit semantics. Neither transport may implement a weaker or separate security control path. See [ADR-0025](../adr/0025-dual-api-transports-shared-security-pipeline.md).

The native API uses semantic versioning and a two-minor-version deprecation policy. These are existing requirements, not Phase 2.0 choices; see [ADR-0015](../adr/0015-reproducible-builds-and-api-versioning.md).

The optional compatibility subset of the HashiCorp Vault API is separate from the native API. It is considered only after the native API is stable and its legal-review condition is satisfied; it is not part of the native Phase 2 operation catalog. See [ADR-0018](../adr/0018-vault-api-compatibility-subset.md).

## 2. Authoritative request pipeline

Every request on either native transport follows the exact order in [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md):

1. TLS 1.3 listener using rustls.
2. HTTP/gRPC server integration and server-generated request ID.
3. Request-size and time limits.
4. IP-based pre-authentication rate limit.
5. Local seal-state check.
6. Authentication.
7. Identity-based rate limit.
8. Canonical route/action and ACL evaluation.
9. Approved operation handler.
10. Durable audit before and after sensitive operations.

The order is security-significant. Middleware, protocol adapters, handlers and error paths must not bypass, reorder or weaken a stage. The minimum sealed-mode surface is an explicit allowlist of non-sensitive endpoints; no general API access while sealed is implied.

## 3. Authentication methods

The approved Community MVP authentication methods are:

- Tokens.
- AppRole.
- mTLS client certificates.
- Username/password, with Argon2id password hashing.

OIDC, Kubernetes authentication and LDAP are deferred and are not part of this MVP. This preserves the owner-approved authentication scope in the source roadmap's Phase 2 definition and its additional approved decision set.

The bootstrap token is one-time. Bootstrap/credential flows must preserve the approved expiry, revocation and replay protections. Authentication must produce a trusted server-side principal. Client-supplied identity or tenant values cannot override that context.

Dynamically dispatched authentication extensions follow [ADR-0002](../adr/0002-async-extension-contracts.md): `async_trait`, `Send + Sync`, and documented cancellation, lifetime, error, concurrency and security guarantees.

## 4. Identity, tenant and authorization

Community is single-tenant. The logical tenant is always `root`, derived from trusted server-side authenticated/authorized context. A client cannot choose or override it. Community uses mounts and ACL for isolation and does not claim cryptographic isolation between tenants; see [ADR-0019](../adr/0019-community-tenant-model.md).

Authorization is deny-by-default and applies to canonicalized paths/resources and capabilities. Route normalization precedes ACL evaluation. Missing, malformed, unavailable or indeterminate policy state must not become an implicit allow. Policy semantics must be identical over HTTP/JSON and gRPC.

The ACL grammar and any detailed matching/precedence rules must be copied from the owner's approved design record; this document does not invent syntax or substitute a new policy model.

## 5. Rate limits and request resource bounds

The ordered pipeline requires two distinct controls:

- IP-based rate limiting before authentication.
- Identity-based rate limiting after successful authentication.

Request-size and time limits apply before expensive or protected processing. The Phase 2 design also includes quotas, concurrency limits and backpressure as resource controls. Client-address derivation must follow the approved trusted-proxy boundary; spoofable forwarding headers must not become authoritative by default.

No numeric quota, burst, window, request-size or timeout value is introduced by this carryover. Where those values were separately approved, they must be transcribed exactly from that approval record.

## 6. Seal and root operations

The seal-state gate precedes authentication. While sealed, only the explicit minimal non-sensitive allowlist is reachable.

The mandatory default Unsealer is Shamir 2-of-3. AWS KMS remains an optional, feature-gated adapter, disabled by default, with no silent provider fallback. A principal with `kms:Decrypt` is a high-impact alternate unseal trust path; it does not satisfy or bypass the separate root-operation quorum. See [ADR-0024](../adr/0024-unsealer-port-and-optional-aws-kms.md).

`generate-root`, root rotation and root revocation each retain the independently configured 2-of-3 root-operation quorum. Missing or invalid quorum configuration fails closed. This is distinct from ordinary API authentication and from the generic offline Shamir 5-of-3 recovery default; see [ADR-0014](../adr/0014-root-ceremony-recovery-and-backups.md).

## 7. Storage and audit

Phase 2 consumes the accepted Community redb storage contract. The contract includes versioned CRUD, paginated prefix listing, atomic transactions with preconditions, CAS and linearizable semantics. Protected values are encrypted before reaching generic storage; see [ADR-0003](../adr/0003-storage-backend-contract.md).

Audit requirements from [ADR-0005](../adr/0005-request-pipeline-and-fail-closed-audit.md):

- Minimum destinations: JSON file with hash-chain integrity, plus stdout/syslog.
- Retention is configurable, with a 90-day default.
- Required audit intent is durable before sensitive side effects or protected-data disclosure.
- The operation outcome is recorded durably afterward.
- Failure to persist required intent blocks the sensitive operation; protected reads do not disclose data first.
- When audit and business state do not share a transaction, use outbox, idempotency and reconciliation.
- A local hash chain is tamper-evident within its threat boundary; it is not a claim of immutable off-host retention against an attacker controlling the host.

Audit payloads, diagnostics, error bodies, test data and fuzz artifacts must not expose credentials, tokens, recovery shares, root material or protected plaintext.

## 8. Clock and time semantics

Durations use a monotonic clock. Certificate validity uses wall-clock time. Clock-drift tolerance and NTP alert behavior must be defined and tested in the relevant implementation phase, preserving [ADR-0014](../adr/0014-root-ceremony-recovery-and-backups.md). The KV/lease engine and its lease operations remain Phase 4; recording shared clock semantics here does not pull that engine into Phase 2.

## 9. Community delivery boundaries

The CLI distribution decision in [ADR-0023](../adr/0023-cli-distribution.md) starts in Phase 2: tar.gz/zip for Linux x86_64/aarch64, a universal macOS build and Windows x86_64. Releases require verifiable checksums and signatures. crates.io publication is not implied and requires a separate owner decision.

The MVP has no web UI. UI work is deferred and must use the same server/API and controls; see [ADR-0021](../adr/0021-user-interface.md). The server distribution and hardening requirements remain those in [ADR-0022](../adr/0022-server-distribution.md).

PKI, KV v2/leases, Transit and encrypted Raft/HA remain in their separately approved roadmap phases. Community must not add Enterprise dependencies or publish Enterprise-only implementation details.

## 10. Provenance gaps to close in Phase 2.0

The owner has stated that the Phase 2 architecture choices were already made. These are carryover and documentation-traceability tasks, not requests to select again. The pinned source baseline and the current Community ADR set establish the binding requirements above, but do not reproduce every low-level value in a directly transcribable route/configuration catalog.

Phase 2.0 must locate and reproduce the previously approved values for the following items before implementation relies on them:

- Exact native HTTP route names, methods, request/response schemas, gRPC service/RPC names and cross-transport error mapping.
- Exact token/credential representations, persistence/validation rules, principal fields and lifecycle durations beyond the one-time bootstrap and stated lifecycle protections.
- The full ACL grammar, capability vocabulary and rule precedence.
- Numerical request limits, rate-limit algorithms/quotas/windows/bursts and trusted-proxy configuration.
- Exact sealed-mode endpoint and response-field allowlist.
- TLS certificate provisioning, trust roots, rotation and reload lifecycle.
- Canonical audit event schema, hash-chain construction parameters, append durability and approved rotation/archive behavior.
- Exact outbox schema, idempotency key rules, recovery/reconciliation transitions, service configuration source, health/readiness fields and graceful shutdown contract.

No value above may be guessed from common practice, Vault compatibility or a new implementation preference. An absent detail in the abridged public ADR is not a reason to reopen an owner-approved decision. Keep Phase 2.0 in progress until the authoritative approved value is transcribed and its Community scope reviewed. Publish only Community-applicable content; do not copy private-edition material.

## 11. Verification requirements

Apply [ADR-0010](../adr/0010-testing-and-security-evidence.md) at the subphase that introduces each boundary:

- Unit and integration tests for validation, ordered pipeline, credential lifecycle, identity, ACL, audit and configuration.
- Property tests for canonical routes, policy invariants, codecs, rate-limit/state invariants and audit-chain continuity.
- Coverage-guided fuzzing for every untrusted HTTP/JSON, gRPC/IDL, credential, policy, route and audit parser/decoder introduced.
- Negative security tests for auth failures, replay, revocation, spoofed client addresses, path confusion, policy bypass, sealed-mode bypass, oversized/slow requests, cancellation, secret leakage and audit sink failure.
- E2E tests against the actual TLS listener over both HTTP/JSON and gRPC, including equivalent allow/deny behavior and attempts to switch transport to bypass a denial.
- Failure injection and restart/recovery tests where persistence, audit or coordination is involved; Loom, Miri and Criterion where applicable.
- At least 90% measured coverage for crypto, seal, policy, auth and audit, as required by ADR-0010. Every discovered defect becomes a deterministic regression test.

Only synthetic credentials, tokens, roots, shares and data may be used in tests, fuzz corpora and CI artifacts. Passing CI is not an external security audit, FIPS validation or production authorization.
