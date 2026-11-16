# Phase 2 — Native service contract and security defaults

- **Status:** Technical contract selected under the owner's explicit delegation on 2026-11-16; pending Phase 2.0 review/acceptance before runtime implementation.
- **Scope:** Ferrum Vault Community only.
- **Normative authority:** Existing owner-approved ADRs remain superior. This document fixes implementation details that those ADRs intentionally left unspecified; it does not rewrite their approved constraints.
- **Machine-readable interfaces:** [OpenAPI](openapi.yaml) for HTTP/JSON and [Protocol Buffers](../../proto/ferrum/v1/service.proto) for gRPC. This document defines their shared semantics.

## 1. Decision authority and precedence

The owner explicitly instructed the technical architect to select the missing details using the most robust, professional, secure and scalable Community design. The decisions below are therefore **new delegated technical selections made on 2026-11-16**. They are not falsely attributed to the original source ADRs or to an unavailable specification. They are selected defaults for the Community Phase 2 contract and are subject to the repository's normal Phase 2.0 review and acceptance gate.

Precedence is:

1. Owner-approved Community ADR requirements, including ADR-0002, 0003, 0005, 0010, 0014, 0015, 0019, 0024 and 0025.
2. This delegated Phase 2 service contract and its machine-readable OpenAPI/protobuf artifacts.
3. Implementation details that do not change externally observable security or compatibility behavior.

A conflict with an approved ADR must be reported and resolved through an explicitly authorized superseding ADR. Do not silently change an approved choice. No Enterprise-only source, dependency or service is permitted.

## 2. Product and phase boundary

Phase 2 supplies the native service control plane: health/readiness, bootstrap and seal lifecycle integration, root-operation quorum ceremonies, the approved authentication methods, identity and credential lifecycle, ACL policy administration, and audit status. It does **not** expose PKI issuance, KV v2/leases, Transit cryptographic operations, Raft/HA, a web UI, OIDC, Kubernetes auth, LDAP or Vault-compatibility routes. Those remain in their approved later phases or exclusions.

Community remains a single logical tenant named `root`. Tenant identity is injected by trusted server context and is never accepted from a request field, URL, HTTP header or gRPC metadata.

## 3. Transport, versioning and wire rules

### 3.1 Listener and protocol negotiation

- One TLS listener serves both native transports. Default bind: `127.0.0.1:8443`; remote exposure requires an explicit operator configuration.
- TLS 1.3 only, using rustls. HTTP/JSON uses HTTP/1.1 or HTTP/2; gRPC uses HTTP/2. ALPN is restricted to `h2` and `http/1.1`.
- TLS 0-RTT/early data is disabled because replayable early data is inappropriate for authentication and state-changing operations.
- No plaintext listener, TLS downgrade, permissive certificate mode or transport-specific security pipeline is provided.
- Both transports enter the exact ADR-0005 ten-stage pipeline. Transport adapters may decode/encode but cannot authenticate, authorize, gate seal state, rate-limit or audit independently.

### 3.2 HTTP/JSON

- The namespace is `/v1`; JSON media type is `application/json`; UTF-8 only.
- The normative machine-readable description is OpenAPI 3.2.1. The contract version remains `v1`; an OpenAPI document revision is not an API breaking change.
- Reject malformed JSON, duplicate object member names, invalid UTF-8, unknown request fields, excessive nesting and unsupported content encodings. Never silently coerce numbers, booleans or identifiers.
- JSON property names are lower camel case. Timestamps are RFC 3339 UTC strings with a `Z` suffix. Binary values are unpadded base64url.
- Clients must tolerate additional response fields. The server rejects unknown request fields in `v1`; additive request fields require an explicitly documented compatibility decision.
- No credentials are accepted in query parameters, URLs or cookies. Bearer tokens are accepted only in the `Authorization: Bearer` header.

### 3.3 gRPC

- The package namespace is `ferrum.v1`; the normative IDL is `proto/ferrum/v1/service.proto`, using proto3.
- gRPC metadata carries the same bearer credential and idempotency key as HTTP headers. Client-supplied principal, tenant, source-IP or request-ID metadata is ignored or rejected; the server constructs trusted context.
- Both transports map to the same internal operation identifier, resource identifier, principal, policy snapshot, rate-limit bucket and audit operation ID.
- Contract tests must prove that switching transport cannot change an allow/deny decision or bypass a seal, rate-limit or audit control.

### 3.4 Request identity, deadlines and idempotency

- Generate a cryptographically random server request ID for every request. Return it as `X-Request-ID` for HTTP and `x-request-id` response metadata for gRPC. Never use a caller-supplied request ID as authority.
- Use one request deadline across decode, authentication, authorization, handler, audit and response. Default deadline is 15 seconds; hard maximum is 30 seconds. Cancellation is propagated to extension points as required by ADR-0002.
- State-changing resource mutations and root-operation initiation require an `Idempotency-Key`: 16 random bytes encoded as unpadded base64url (22 characters). Its scope is principal + canonical operation + key; retention is 24 hours. Bootstrap consumption, unseal-session creation/share submission and root-share approvals instead use one-time credentials, short-lived server sessions and participant replay detection; their secret material is never cached or retried as a new participant.
- The server stores a digest of the canonical request, never the raw key. A repeat with the same key and same request returns the original non-secret operation result/reference. Reuse with a different request returns HTTP 409 / gRPC ALREADY_EXISTS. Credentials, unseal/root shares and secret-bearing responses are never replay-cached or reissued on retry. A repeated token/Secret ID issuance request returns HTTP 200 or gRPC OK with `replayed=true`, its non-secret accessor and expiry, and an empty/omitted credential secret. The caller may revoke the issued credential by accessor if the original secret response was lost. A different request using the same key returns HTTP 409 / gRPC ALREADY_EXISTS.
- The idempotency record and state transition must be atomic when the backend supports it. For one-time credential issuance, persist a one-time secret reveal state and a non-secret accessor receipt atomically with issuance: exactly one response may expose the secret; all replays expose only the receipt. Otherwise use the durable outbox/reconciliation contract in Section 11.

## 4. Canonical operation catalog

The exact route and RPC names below are binding for Phase 2.1. The security pipeline is applied uniformly to every listed operation.

| Operation | HTTP method and path | gRPC method | Authentication / ACL | Available while sealed | Audit |
|---|---|---|---|---|---|
| Liveness | `GET /v1/sys/health/live` | `SystemService.GetLiveness` | Public, IP-limited | Yes | No |
| Readiness | `GET /v1/sys/health/ready` | `SystemService.GetReadiness` | Public, IP-limited | Yes | No |
| Seal status | `GET /v1/sys/seal-status` | `SystemService.GetSealStatus` | Public, IP-limited | Yes | No |
| Consume bootstrap | `POST /v1/sys/bootstrap/consume` | `SystemService.ConsumeBootstrapToken` | One-time bootstrap token | Only while uninitialized | Required intent/outcome |
| Start unseal session | `POST /v1/sys/unseal/sessions` | `SystemService.CreateUnsealSession` | No bearer token; Shamir ceremony gate | Yes | Attempt/result metadata only |
| Submit unseal share | `POST /v1/sys/unseal/sessions/{sessionId}/shares` | `SystemService.SubmitUnsealShare` | One valid FRS1 share per distinct participant | Yes | Attempt/result metadata only |
| Seal | `POST /v1/sys/seal` | `SystemService.Seal` | Authenticated; `sys/seal:execute` | No | Required intent/outcome |
| Password login | `POST /v1/auth/password/login` | `AuthService.PasswordLogin` | Password credential | No | Authentication outcome |
| AppRole login | `POST /v1/auth/approle/login` | `AuthService.AppRoleLogin` | Role ID + Secret ID | No | Authentication outcome |
| Token lookup-self | `POST /v1/auth/token/lookup-self` | `TokenService.LookupSelf` | Current bearer token | No | Security event |
| Token renew-self | `POST /v1/auth/token/renew-self` | `TokenService.RenewSelf` | Current bearer token | No | Required intent/outcome |
| Token revoke-self | `POST /v1/auth/token/revoke-self` | `TokenService.RevokeSelf` | Current bearer token | No | Required intent/outcome |
| Create child token | `POST /v1/sys/auth/tokens` | `TokenService.CreateToken` | `auth/token:create` | No | Required intent/outcome |
| Revoke token by accessor | `DELETE /v1/sys/auth/tokens/{accessor}` | `TokenService.RevokeToken` | `auth/token:delete` | No | Required intent/outcome |
| Create password user | `POST /v1/sys/auth/password/users` | `IdentityService.CreatePasswordUser` | `auth/password-users:create` | No | Required intent/outcome |
| Read password user | `GET /v1/sys/auth/password/users/{userId}` | `IdentityService.GetPasswordUser` | `auth/password-users:read` | No | Security event |
| Update password user | `PATCH /v1/sys/auth/password/users/{userId}` | `IdentityService.UpdatePasswordUser` | `auth/password-users:update` | No | Required intent/outcome |
| Delete password user | `DELETE /v1/sys/auth/password/users/{userId}` | `IdentityService.DeletePasswordUser` | `auth/password-users:delete` | No | Required intent/outcome |
| Create AppRole | `POST /v1/sys/auth/approle/roles` | `AppRoleService.CreateRole` | `auth/approle:manage` | No | Required intent/outcome |
| List AppRoles | `GET /v1/sys/auth/approle/roles` | `AppRoleService.ListRoles` | `auth/approle:read` | No | Security event |
| Read AppRole | `GET /v1/sys/auth/approle/roles/{name}` | `AppRoleService.GetRole` | `auth/approle:read` | No | Security event |
| Update AppRole | `PUT /v1/sys/auth/approle/roles/{name}` | `AppRoleService.UpdateRole` | `auth/approle:manage` | No | Required intent/outcome |
| Delete AppRole | `DELETE /v1/sys/auth/approle/roles/{name}` | `AppRoleService.DeleteRole` | `auth/approle:manage` | No | Required intent/outcome |
| Issue AppRole Secret ID | `POST /v1/sys/auth/approle/roles/{name}/secret-ids` | `AppRoleService.CreateSecretId` | `auth/approle:manage` | No | Required intent/outcome |
| Revoke AppRole Secret ID | `DELETE /v1/sys/auth/approle/roles/{name}/secret-ids/{accessor}` | `AppRoleService.RevokeSecretId` | `auth/approle:manage` | No | Required intent/outcome |
| List ACL policies | `GET /v1/sys/policies/acl` | `PolicyService.ListPolicies` | `sys/policy:read` | No | Security event |
| Read ACL policy | `GET /v1/sys/policies/acl/{name}` | `PolicyService.GetPolicy` | `sys/policy:read` | No | Security event |
| Create/update ACL policy | `PUT /v1/sys/policies/acl/{name}` | `PolicyService.PutPolicy` | `sys/policy:manage` | No | Required intent/outcome |
| Delete ACL policy | `DELETE /v1/sys/policies/acl/{name}` | `PolicyService.DeletePolicy` | `sys/policy:manage` | No | Required intent/outcome |
| Begin root operation | `POST /v1/sys/root-operations` | `RootService.BeginOperation` | Authenticated; `sys/root:execute` | No | Required intent/outcome |
| Approve root operation | `POST /v1/sys/root-operations/{operationId}/approvals` | `RootService.ApproveOperation` | Authenticated; unique principal and distinct valid root-share participant | No | Required intent/outcome |
| Read root-operation status | `GET /v1/sys/root-operations/{operationId}` | `RootService.GetOperation` | `sys/root:read` | No | Security event |
| Audit status | `GET /v1/sys/audit/status` | `AuditService.GetStatus` | `sys/audit:read` | No | Security event |

Only one root-operation session may be active globally. The root quorum policy must be explicitly configured as threshold 2 of 3 total shares; missing/invalid configuration blocks root operations and never selects a fallback. Root-operation shares belong to an independent root-key FRS1 ceremony, never the seal/unseal share set. Each approval must come from a different authenticated principal and a distinct FRS1 participant ID, with policy `threshold=2/share_count=3` and the configured root ceremony ID. The operation ID and action bind the submission to the active five-minute ceremony. Record only `SHA-256(ASCII("FerrumVaultCommunityRootParticipantV1") || 0x00 || ceremony_id_16_bytes || participant_id_u8)` for duplicate/replay prevention, scoped to the operation ID; never store share bytes. Zeroize share bytes immediately. The response exposes only operation state and the fixed threshold, never the number of approvals or participant identity. A duplicate principal, duplicate participant, wrong ceremony or expired operation is rejected. Root-operation shares never enter durable storage, audit payloads, logs, metrics or traces.

The OpenAPI and protobuf artifacts are the authoritative field-level schemas. The operation catalog intentionally excludes all KV, PKI, Transit and HA routes until their own roadmap phases.

## 5. Shared response and error contract

### 5.1 Success

- Successful resource responses use operation-specific typed schemas, as defined in OpenAPI/proto3. Authentication responses use an `auth` object. Empty success uses HTTP 204 / gRPC OK with no body.
- Every response carries the server-generated request ID in its transport metadata/header.
- Resource revisions are opaque ETags. Policy creation requires `If-None-Match: *`; policy updates/deletes and identity/AppRole mutations require `If-Match`. Missing or mutually conflicting preconditions return 428; stale revisions return 412. The gRPC equivalent carries an expected revision (zero only for creation) and returns FAILED_PRECONDITION on mismatch.
- List operations use an opaque, integrity-protected cursor bound to principal, query and page size. Default page size 50; maximum 100; cursor lifetime 5 minutes.

### 5.2 Errors

HTTP errors use RFC 9457 Problem Details with `Content-Type: application/problem+json` and stable extension fields `code`, `requestId` and `retryable`. Never return stack traces, file paths, SQL/DB details, credential validity distinctions or secret-bearing diagnostics.

The gRPC adapter maps the same domain error to canonical gRPC status codes and a `google.rpc.Status` detail carrying the same stable `code` and request ID. The HTTP and gRPC codes must be semantically equivalent.

| Domain error | HTTP | gRPC |
|---|---:|---|
| Invalid input / malformed schema | 400 | INVALID_ARGUMENT |
| Missing/invalid/expired credential | 401 | UNAUTHENTICATED |
| Authenticated but not authorized | 403 | PERMISSION_DENIED |
| Absent resource | 404 | NOT_FOUND |
| State conflict / duplicate idempotency key | 409 | ALREADY_EXISTS or ABORTED |
| Failed state/precondition | 412 | FAILED_PRECONDITION |
| Missing required conditional header | 428 | FAILED_PRECONDITION |
| Body/message too large | 413 | RESOURCE_EXHAUSTED |
| Rate limit / concurrency quota | 429 | RESOURCE_EXHAUSTED |
| Deadline exceeded | 504 | DEADLINE_EXCEEDED |
| Audit/storage/dependency unavailable | 503 | UNAVAILABLE |
| Unexpected internal failure | 500 | INTERNAL |

All password and AppRole login failures use the same public error class and message to avoid account/role enumeration. The response never states whether the principal exists, whether a password was wrong or whether a Secret ID was revoked.

## 6. Authentication and credential lifecycle

### 6.1 Opaque API tokens

- Token format: `fvct_` followed by 32 CSPRNG bytes encoded as unpadded base64url (43 encoded characters). The secret is returned exactly once. Store only `SHA-256(ASCII("FerrumVaultCommunityTokenV1") || 0x00 || token_random_32_bytes)` plus encrypted metadata; never store the plaintext token.
- Tokens are opaque random bearer credentials, not self-contained JWTs. The server stores a SHA-256 digest with domain separation, plus encrypted metadata. Plaintext tokens never enter storage, logs, audit, metrics, traces or test artifacts.
- An accessor is a random 128-bit non-secret handle. It is not accepted for authentication and cannot reveal a token. It is returned with token issuance and is the only handle accepted by the revoke-by-accessor route.
- Default access-token TTL: 15 minutes. Standard maximum TTL: 8 hours. Privileged/root-administration token TTL: 5 minutes, absolute maximum 15 minutes, non-renewable.
- A token may contain only policy references that are a subset of the issuing principal's effective policies. No token may grant capabilities its issuer does not possess. Child tokens are revoked when the parent is revoked. Orphan tokens are not available in Phase 2.
- Renewal rotates the bearer secret: it atomically revokes the old token and returns a new random token with the same or narrower policy set and a deadline no later than the original maximum TTL. The new token accessor is returned with the secret once. An idempotency replay returns only the non-secret accessor/expiry receipt; it never repeats the secret. Reuse of the old value fails immediately.
- Revocation by self or accessor is immediate. Revocation records are durable and audited. No offline token-validation mode is provided.

### 6.2 Username/password

- User names are case-insensitive ASCII identifiers matching `[a-z0-9][a-z0-9._-]{2,63}`; immutable internal user IDs are UUIDs.
- Passwords accept 12–1024 UTF-8 bytes; never truncate or silently normalize. Do not impose periodic password changes or arbitrary character-composition rules.
- Hash using Argon2id v=19, memory 65,536 KiB, iterations 3, parallelism 4, 16-byte unique random salt and 32-byte output. This is RFC 9106's second recommended profile for environments with much less memory than the 2 GiB first-recommended profile; it is selected for a bounded Community server memory budget, not represented as the highest-memory profile. Store the self-describing encoded hash, encrypted at rest through the accepted Phase 1 protected-storage boundary. Rehash after successful authentication when parameters are below the configured current policy.
- Limit concurrent Argon2 computations to 4, with a bounded queue of 8; reject excess work with 429/RESOURCE_EXHAUSTED. Use the same Argon2id profile for existing and nonexistent users (dummy hash) to reduce timing-based enumeration. Compare results in constant time and zeroize password buffers.
- Successful login returns a standard short-lived opaque token. Failed login never returns distinct messages for unknown user and wrong password.

### 6.3 AppRole

- `role_id` is a random 128-bit public identifier encoded as unpadded base64url. `secret_id` is the `fvsa_` prefix followed by a random 256-bit secret encoded as unpadded base64url, shown once; store only `SHA-256(ASCII("FerrumVaultCommunityAppRoleSecretV1") || 0x00 || secret_id_random_32_bytes)`. Its response includes a separate random 128-bit accessor. A repeated idempotency key returns only that non-secret accessor, expiry, use count and `replayed=true`; it never reissues the secret. The accessor can immediately revoke the Secret ID through `RevokeSecretId`.
- Default Secret ID TTL is 24 hours, maximum 30 days, and default use count is one. A role may explicitly configure at most 10 uses; unlimited-use Secret IDs are forbidden.
- Role token TTL defaults to 15 minutes and is capped at 1 hour. Policies issued by a role are fixed at role configuration and cannot be expanded by login input.
- Optional CIDR binding is checked against the trusted peer address, never a client-supplied forwarding header. Secret ID expiry/use decrement is atomic and replay-safe.

### 6.4 mTLS client identity

- A verified TLS client certificate may authenticate a request without a bearer token when the operation permits mTLS.
- Require a valid chain to an explicitly configured client trust anchor, current validity, clientAuth EKU and an exact URI SAN-to-principal mapping. CN fallback, wildcard mapping and client-certificate identity headers are forbidden.
- Certificate revocation is checked against the configured local CRL/revocation material. Missing, invalid or expired required revocation data fails mTLS authentication closed.
- Server and client trust bundles are separate. Mapping changes and revocation material reload atomically; a failed reload retains the previous known-good snapshot and emits an audit/security event.

### 6.5 Bootstrap and identity ownership

- The initial bootstrap token is generated out-of-band by the local CLI, uses the `fvbt_` prefix followed by 32 random bytes encoded as unpadded base64url, is stored only as `SHA-256(ASCII("FerrumVaultCommunityBootstrapV1") || 0x00 || token_random_32_bytes)` and expires after 5 minutes. It may be consumed once, only while the service is uninitialized. Its response is one-time; a lost response requires the local operator to restart the bootstrap procedure through the local CLI while the service remains uninitialized, not an unauthenticated API replay.
- Consuming it issues a one-time bootstrap administration token limited to creating the first password identity and initial ACL policy. It cannot read protected data, create general tokens or perform root operations. It expires after 5 minutes and is revoked automatically when initial setup completes.
- All principal IDs, tenant values, roles and credential metadata are resolved by the server. No client identity or tenant field is authoritative.

## 7. ACL policy language and authorization

### 7.1 Policy representation

Policies use versioned JSON objects in the machine-readable contract, not an embedded scripting language:

```json
{
  "version": 1,
  "rules": [
    {
      "effect": "allow",
      "resource": "auth/approle/*",
      "actions": ["read", "manage"]
    },
    {
      "effect": "deny",
      "resource": "sys/root/**",
      "actions": ["execute"]
    }
  ]
}
```

Each rule has exactly `effect` (`allow` or `deny`), `resource` and a non-empty list of `actions`. Version 1 supports only the fixed action vocabulary `read`, `create`, `update`, `delete`, `list`, `execute` and `manage`. `manage` is an exact, distinct action and does not implicitly grant `read`, `list` or `execute`; policies must enumerate every required action. Conditions, templates, interpolation, regex, user-defined functions, policy includes and arbitrary expressions are deliberately excluded from v1.

### 7.2 Canonical resources and matching

- The server maps each HTTP route and gRPC method to one canonical operation ID, resource ID and action before authorization. The client cannot submit an alternative resource/action for evaluation.
- Canonical resource segments are case-sensitive ASCII lower-case identifiers. A segment matches `[a-z0-9][a-z0-9._-]{0,62}`; empty segments, dot segments, encoded separators, backslashes, control characters and invalid UTF-8 are rejected.
- URL percent-encoding is decoded exactly once by the transport adapter before route matching. Encoded slash/backslash, double-encoding, dot-segment traversal and ambiguous normalization are rejected, not normalized into a different resource.
- ACL resource patterns contain literal segments, `*` for exactly one segment and optional terminal `**` for zero or more trailing segments. `**` anywhere except the final segment is invalid. Wildcards never cross a mount/tenant boundary because the resource identifier already includes the canonical mount boundary.
- A rule's action list is an exact set; there is no action wildcard.

### 7.3 Evaluation and lifecycle

- Default is deny. Any matching deny overrides all matching allows. Otherwise a request is allowed only if at least one matching allow rule grants the exact action.
- Missing policy, corrupt policy, unsupported policy version, timeout, policy-store failure or ambiguous resource mapping is deny.
- Effective identity policy is the union of the identity's policy references followed by deny-overrides evaluation. The immutable bootstrap policy exists only during first setup. No implicit administrator bypass exists.
- Policies have monotonically increasing revisions. Update/delete uses compare-and-swap semantics; HTTP requires `If-Match`. Every policy change is audited before and after activation.
- Evaluation uses one immutable policy snapshot per request, preventing mid-request rule changes from producing inconsistent authorization.

## 8. Exact sealed-mode allowlist

While sealed, all operations are denied except:

1. `GET /v1/sys/health/live`
2. `GET /v1/sys/health/ready`
3. `GET /v1/sys/seal-status`
4. `POST /v1/sys/bootstrap/consume`, only if uninitialized and the one-time bootstrap token is valid
5. `POST /v1/sys/unseal/sessions`
6. `POST /v1/sys/unseal/sessions/{sessionId}/shares`

No token login, AppRole login, password login, token lookup, policy API, audit configuration, root operation or protected handler is available while sealed. Unknown paths return the same generic sealed/unavailable response and do not reveal whether a protected route exists.

Health responses expose only the minimum needed by probes. Seal status contains `initialized`, `sealed` and the configured threshold; it never contains participant IDs, submitted-share count, share bytes, root identifiers, storage paths, key metadata or detailed failure causes.

Unseal uses one active in-memory session with a five-minute TTL. Each submission contains exactly one canonical binary FRS1 envelope already defined by `ferrum-recovery`; Phase 2 does not invent another share format. HTTP represents the exact FRS1 bytes as unpadded base64url in the `share` JSON string; gRPC carries the same bytes in the `bytes share` field and includes `session_id`. Decode strictly (no padding, whitespace, alternate alphabets or trailing data; the decoded envelope is bounded by the common 1 MiB HTTP/gRPC message limit) into zeroizing memory, then call the existing strict `RecoveryShare::decode`. Verify FRS1 version 1, policy `threshold=2/share_count=3`, the configured unseal ceremony ID and a participant ID not previously accepted. The server verifies it belongs to the current ceremony and accepts only distinct participant IDs. On the second distinct valid share the existing Shamir 2-of-3 Unsealer is invoked. Share bytes are held only in zeroizing memory and erased immediately after validation/combination; they are never written to disk, audit, logs, metrics or traces. The response never reveals how many shares have been submitted or participant identifiers. Sessions and shares are erased on success, invalidation, timeout, cancellation or process restart. Restart leaves the service sealed. No KMS fallback is attempted; optional AWS KMS selection remains explicit under ADR-0024.

## 9. Request and resource limits

All limits are enforced before expensive parsing/handler work and remain configurable within safe hard bounds.

| Control | Default | Hard maximum / behavior |
|---|---:|---|
| HTTP request body | 1 MiB | 1 MiB in Phase 2 |
| FRS1 share envelope | 1 MiB decoded gRPC message; HTTP base64url representation is bounded by the 1 MiB request-body limit | Same transport-independent 1 MiB logical-message ceiling |
| gRPC receive/send message | 1 MiB | 1 MiB in Phase 2 |
| HTTP header bytes | 16 KiB | 16 KiB |
| Request target / path | 8 KiB | 8 KiB |
| JSON nesting depth | 32 | 32 |
| JSON string value | 256 KiB | 256 KiB |
| List page size | 50 | 100 |
| Header read timeout | 5 s | 5 s |
| Body read timeout | 10 s | 10 s |
| Request deadline | 15 s | 30 s |
| Keep-alive idle timeout | 60 s | 60 s |
| Concurrent connections | 512 | 512 |
| In-flight requests | 256 | 256 |
| Concurrent Argon2id computations | 4 | 4 |
| Argon2id waiting queue | 8 | 8 |
| ACL rules per policy | 256 | 256 |
| Active unseal sessions | 1 | 1 |
| Unseal session lifetime | 5 min | 5 min |
| Root-operation approval session | 5 min | 5 min |

Rate-limit defaults:

- Pre-authentication general traffic: 60 requests/minute per trusted source IP, burst 20.
- Password/AppRole login: 10 attempts/minute per source IP and 5 attempts/minute per normalized user/role identifier. Use progressive delay; do not permanently lock an account based solely on remote failures.
- Unseal share submissions: 5 attempts per 15 minutes per source IP; invalid shares count.
- Authenticated identity: 600 requests/minute, burst 120; administrative mutation: 60/minute, burst 10.
- Root-operation approvals: 10 attempts/hour per principal, additionally limited by the two-of-three ceremony state. Only one root mutation may be active at a time.
- Global overload or bounded-queue exhaustion returns 429 or 503. Rate limiting is never silently disabled when its state backend is unavailable.

Community Phase 2 is one service instance. Rate-limit state and lockout counters are persisted using the accepted redb boundary where persistence is required; in-memory token buckets are only an additional fast front gate. Future multi-instance execution must provide a shared atomic rate-limit backend before it may claim cluster-wide enforcement.

The default source address is the actual socket peer. `Forwarded` is trusted only when the immediate peer is inside explicit `trusted_proxy_cidrs`; parse at most five hops from right to left, stop at the first untrusted hop and reject malformed/obfuscated chains. `X-Forwarded-For` and arbitrary gRPC metadata are never trusted. With no configured proxies, forwarded headers are ignored.

## 10. TLS and certificate lifecycle

- Server TLS is TLS 1.3 only using rustls; 0-RTT is disabled. Certificate/key files are local, explicitly configured paths. Production self-signed and insecure-verification modes are not supported.
- Server certificate must be currently valid, chain to the configured trust model, match the private key, contain the required DNS/IP SANs and serverAuth EKU. The private key file is readable only by the service account (0600 on Unix); certificate files and trust bundles are not writable by the service identity unless explicitly required for controlled reload.
- Client mTLS trust anchors, URI SAN mapping and CRL are separate from server certificate trust. No CN fallback.
- Reload is atomic: parse and validate the full new bundle before swapping the active TLS configuration. Invalid reload retains the previous known-good snapshot, rejects new invalid identities, and raises a security/health event. Existing connections are drained within the configured shutdown policy.
- TLS private keys are never placed in application config values, environment variables, logs, audit or command-line arguments; config stores file paths only.
- Do not trust client certificate headers inserted by a reverse proxy. If a proxy terminates TLS, it must establish a separately authenticated TLS connection to the service; proxy identity headers do not replace service-side TLS verification.

## 11. Durable audit, hash chain, outbox and reconciliation

### 11.1 Canonical event

An audit event contains only an allowlisted set of fields:

- `schemaVersion` (initial value `1`), `eventId` (UUIDv7), `sequence` (strictly increasing base-10 uint64 string to avoid JSON integer precision loss), `occurredAt` (UTC RFC 3339), `eventType` (`intent`, `outcome`, `auth`, `security`), `operationId`, `requestId`, `transport`, `principalId` (or a non-reversible anonymous marker), `authMethod`, `tenantId=root`, `operation`, `resource`, `action`, `decision`, `outcome`, `reasonCode`, `sourceAddress`, `durationMs`, `policyRevision` and `previousHash`.
- No request or response bodies are logged. Never record passwords, bearer tokens, Secret IDs, bootstrap tokens, Shamir shares, root material, private keys, plaintext secrets, Authorization headers or raw idempotency keys.
- Canonicalize the event payload using RFC 8785 JCS. Each JSONL line has the shape `{ "event": <event>, "hash": <lowercase-hex-sha256> }`. Compute `hash = SHA-256(ASCII("FerrumVaultCommunityAuditV1") || 0x00 || previous_hash_32_bytes || sequence_u64_be || JCS(event))`; `previousHash` in the event is the 64-character lowercase-hex encoding of `previous_hash_32_bytes`. The first record uses 32 zero bytes as the genesis hash. `sequence` is a base-10 uint64 string; encode its numeric value as unsigned 64-bit big-endian in the hash input. The domain label, event schema and serialization are versioned; changing any requires a new audit schema version and verifier migration.
- The JSONL file is append-only for the process, opened without following symlinks, owned by the service account and protected by restrictive directory/file permissions. A single-writer lock prevents two Community processes from appending to the same chain.
- Each required intent/outcome append is written completely and synchronized to stable storage before the dependent side effect or response is released. Segment rotation preserves the previous segment's terminal hash. Default retention is 90 days and configurable; retention deletion must preserve a verifiable chain checkpoint and emit an administrative audit event.
- stdout is enabled as a second minimum destination by default. TLS syslog is an optional remote sink; UDP syslog is not used for security audit. The durable hash-chained file is the authoritative local intent/outcome sink. Secondary sink failure is visible and retried but does not replace a failed authoritative append.

### 11.2 Required audit ordering

- For sensitive mutations, persist a durable intent before the side effect. Persist the outcome before returning success.
- For protected reads, persist and synchronize an intent before decrypting/disclosing protected data; persist the outcome before releasing the response body.
- Authentication success/failure and credential creation, renewal, revocation, seal/root operations, policy changes and audit-health transitions produce security-relevant events. Failure to durably record a required authentication/credential or sensitive-operation event fails closed.
- A denial may be recorded as a security event, but a flood of denied probes must not consume an unbounded audit queue or make the process write attacker-controlled payloads to disk.

### 11.3 Outbox and exactly-once boundaries

- Where a state mutation and audit event can share a redb transaction, persist the state transition, operation ID, idempotency record and audit-outbox intent atomically.
- Where they cannot share a transaction, first persist the outbox intent and idempotency record durably; only then execute an idempotent handler. Append/synchronize the outcome event and mark the outbox record delivered.
- Outbox records include operation ID, canonical operation/resource, request digest, principal reference, intent time, attempt count, state and a redacted outcome code. They never contain raw request/response bodies or secrets.
- Retry delivery with bounded exponential backoff; never silently drop, reorder or mark an event delivered before the sink confirms durability.
- On restart, reconcile every pending/ambiguous outbox operation against durable operation state. If the result cannot be proven, mark it `indeterminate`, block duplicate execution and require an explicit repair path. Do not guess whether the operation succeeded.
- Defaults: maximum pending outbox 10,000 events and oldest pending age 60 seconds. Crossing either threshold makes readiness false and rejects new sensitive operations until recovery. Safe liveness/seal-status operations remain available.
- A protected read is never cached in the outbox or idempotency store. A client timeout after a mutation is resolved through the operation ID/idempotency key, not by blindly retrying with a new key.

The hash chain is tamper-evident within the host trust boundary. It is not immutable off-host retention against an attacker controlling the host; remote TLS syslog or a separately administered archive is required for that stronger threat model.

## 12. Configuration and startup behavior

The service uses a strict TOML configuration file. Unknown keys, duplicate keys, invalid types, unsafe paths, invalid durations and out-of-range values fail validation; there is no silent fallback. Configuration precedence is defaults < file < explicitly documented `FERRUM__...` environment overrides < CLI flags. Secret values are not accepted through environment variables or CLI; only references/paths are allowed.

Security-critical settings (listener, trust anchors, proxy trust, auth TTL ceilings, audit durability, storage path and rate limits) require restart to change. TLS certificate/key and client CRL bundle reload is the only supported hot-reload path in Phase 2, and reload is atomic.

See [configuration-contract.md](configuration-contract.md) and [the synthetic example](../../examples/ferrum.phase2.example.toml). A config validation command must fail before opening a listener if any required control is unsafe or unavailable.

## 13. Clock and lifecycle semantics

Preserve ADR-0014: monotonic clock for elapsed durations, TTL enforcement during a process, rate windows, timeouts and ceremony expiry; UTC wall clock for certificate validity and persisted absolute expiry. Store both issuance and expiry timestamps for persisted credentials, and never extend a credential after restart because a clock moved backward.

Persist a wall-clock high-water mark. A backward jump greater than 30 seconds places the service in `clock_unsafe`: readiness is false, new credentials/renewals and certificate-based authentication fail closed, and an explicit security event is emitted. A forward jump may expire credentials early but must never extend their lifetime. Recovery requires the wall clock to catch up or an explicit local operator acknowledgement after time synchronization is verified. No API request may set server time.

## 14. Required security verification

Apply ADR-0010 and fuzzing in the same subphase that introduces each parser or state machine. The minimum Phase 2 evidence is:

- OpenAPI lint and generated-client/schema validation; protobuf lint, compatibility check and generated-code consistency.
- HTTP and gRPC contract tests proving the same operation, status semantics, identity, ACL decision, seal behavior and audit behavior.
- TLS 1.3-only tests; no TLS 1.2, no plaintext, no 0-RTT; certificate expiry, wrong EKU/SAN, invalid chain, expired CRL and atomic reload failures.
- Authentication tests for wrong/expired/revoked/replayed credentials, token rotation, child-token subset rules, AppRole use-count races, password timing path, mTLS identity mapping and concurrency limits.
- Property/fuzz tests for JSON, Protobuf, base64url, FRS1 share inputs, canonical routes, ACL parser/matcher, cursor, configuration and audit event/hash decoders.
- Negative tests for duplicate JSON keys, path traversal/encoding confusion, transport-switch bypass, spoofed forwarding headers, principal/tenant injection, unknown fields, oversize/slow requests, rate-limit backend failure and queue exhaustion.
- Audit/outbox tests for concurrent append ordering, fsync failure, tamper, truncation, duplicate idempotency key, crash between intent/effect/outcome, restart reconciliation and fail-closed protected reads.
- Coverage reports for the ADR-0010 targets; deterministic regression tests for every discovered defect; Miri/Loom/Criterion where applicable.
- Only synthetic credentials, root material, shares and data in tests/fuzz/CI artifacts.

Passing documentation checks is not runtime implementation, production authorization, an independent security audit or FIPS validation.

## 15. Standards and references

- [RFC 9846 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc9846.html) (current TLS 1.3 specification; supersedes RFC 8446).
- [RFC 9457 — Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc9457.html).
- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html), used only for deterministic audit serialization.
- [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106.html).
- [OpenAPI Specification 3.2.1](https://spec.openapis.org/oas/v3.2.1.html).
- [gRPC authentication guidance](https://grpc.io/docs/guides/auth/).
- [OWASP API Security Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/), especially broken object/function authorization, authentication and unrestricted resource consumption.

These references inform the selected contract; they do not replace the binding ADRs or authorize a new Enterprise dependency.
