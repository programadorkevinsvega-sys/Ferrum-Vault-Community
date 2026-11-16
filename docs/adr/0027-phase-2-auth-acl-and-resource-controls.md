# ADR-0027: Phase 2 authentication, ACL and resource controls

- **Status:** Delegated technical selection recorded on 2026-11-16; requires Phase 2.0 owner acceptance before runtime implementation.
- **Scope:** Ferrum Vault Community Phase 2.
- **Supersedes:** No existing ADR. Preserves the authentication methods, tenant model, request pipeline and fail-closed ACL requirements in ADR-0005, ADR-0014, ADR-0019 and ADR-0024.
- **Specification:** [Phase 2 service contract](../phase-2/service-contract.md) and [configuration contract](../phase-2/configuration-contract.md).

## Decision

### Credential design

- Use opaque 256-bit CSPRNG bearer tokens with prefix `fvct_`; return the secret once and store only its domain-separated SHA-256 digest. Do not use self-contained JWTs in Phase 2.
- Default token TTL is 15 minutes, standard absolute maximum 8 hours. Privileged tokens default to 5 minutes, maximum 15 minutes and are non-renewable. Renewal rotates the secret and atomically revokes the old token. No orphan tokens or policy escalation.
- Username/password uses Argon2id v=19, 64 MiB memory, 3 iterations, 4 lanes, 16-byte random salt and 32-byte output. This is RFC 9106's second recommended profile for much lower memory budgets; it is selected to bound Community server memory consumption, not claimed as the highest-memory profile. Hashes are protected at rest. Hash concurrency is bounded to 4 with a queue of 8.
- AppRole role IDs are public 128-bit identifiers; Secret IDs are 256-bit one-time secrets, stored only as domain-separated SHA-256 digests. Each Secret ID has a separate non-secret 128-bit accessor and immediate revoke-by-accessor endpoint. Secret ID default TTL is 24 hours, maximum 30 days; default use count 1, maximum 10; unlimited-use IDs are prohibited. Role token TTL defaults to 15 minutes and is capped at 1 hour. Idempotency replay returns accessor/expiry/use-count receipt only, never the secret.
- Bootstrap tokens are generated out-of-band, 256-bit, single-use and valid for 5 minutes. The resulting setup token is also single-use/5-minute and limited to creating the first password identity and initial ACL policy.
- mTLS identity requires a valid clientAuth certificate chain, exact URI SAN-to-principal mapping and active revocation material. CN fallback and proxy-supplied certificate identity headers are forbidden.

### ACL

- Use a versioned JSON policy schema with fixed fields `version`, `rules`, `effect`, `resource` and `actions`. Do not embed a scripting language. `manage` is an exact independent action and does not imply `read`, `list` or `execute`; each permission is explicit.
- Action vocabulary is fixed: `read`, `create`, `update`, `delete`, `list`, `execute`, `manage`.
- Resource patterns use literal canonical segments, `*` for exactly one segment and terminal `**` for trailing segments. No regex, interpolation, arbitrary conditions or action wildcard in v1.
- Deny-by-default; any matching deny overrides any allow. Missing, malformed, stale, unavailable or indeterminate policy state denies.
- Policy updates use revision/CAS semantics and an immutable policy snapshot per request. HTTP uses `If-Match`.

### Resource controls

Adopt the conservative, explicit limits in [configuration-contract.md](../phase-2/configuration-contract.md): 1 MiB HTTP/gRPC message limit, 16 KiB headers, 8 KiB request target, JSON depth 32, default/max page sizes 50/100, 15-second default request deadline (30-second hard maximum), 512 connections, 256 in-flight requests and bounded Argon2 concurrency.

Rate limits are mandatory: pre-auth IP, login IP+identifier, unseal IP, post-auth identity and administrative mutation buckets. Rate-limit backend failure never disables enforcement. Trusted `Forwarded` is honored only from explicitly configured immediate proxy peers; `X-Forwarded-For` is never authoritative.

## Root-operation quorum ceremony

- Root operations remain governed by the separately approved root-operation 2-of-3 quorum (ADR-0014), not by the unseal quorum and not merely by API authentication.
- The operator must explicitly configure `[ceremony.root_quorum]` as `threshold = 2`, `total_shares = 3`; no implicit default or alternate fallback is allowed. Missing/invalid configuration blocks root operations.
- At most one root mutation session may be active globally, with a five-minute lifetime. Every approval requires a different authenticated principal and a distinct valid FRS1 participant share bound to the configured root ceremony and active operation. The server accepts only FRS1 v1 with 2-of-3 policy; root-operation shares come from an independent root-key ceremony and cannot be substituted with the seal/unseal shares.
- Share bytes are held only in zeroizing memory and never persisted, logged, audited, traced or emitted as metrics. The service may persist only a domain-separated participant fingerprint for duplicate/replay prevention. API responses expose operation state and the fixed threshold, not the number of shares/approvals or participant identity.

## Rationale

Opaque tokens make revocation immediate and avoid signing-key/claim drift. Bounded password hashing balances RFC 9106's memory-hard protection with controlled concurrency and predictable resource consumption. A deliberately small ACL grammar is easier to review, fuzz and reason about than a custom policy scripting language. Explicit resource bounds address the unrestricted resource-consumption risk identified by OWASP API4:2023.

## Verification

Test token secrecy, revocation/rotation races, child-policy subset invariants, AppRole one-use races, Argon2 concurrency, mTLS mapping/revocation, ACL precedence and canonicalization, denied-by-default behavior, rate-limit boundaries, proxy spoofing, oversized/slow requests and backend failure. Property-test and fuzz every parser and matcher.
