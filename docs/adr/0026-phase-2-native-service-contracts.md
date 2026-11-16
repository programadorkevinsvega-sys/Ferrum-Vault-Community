# ADR-0026: Phase 2 native service contracts

- **Status:** Delegated technical selection recorded on 2026-11-16; requires Phase 2.0 owner acceptance before runtime implementation.
- **Scope:** Ferrum Vault Community native Phase 2 service.
- **Supersedes:** No existing ADR. This record supplements ADR-0005, ADR-0015 and ADR-0025.
- **Specification:** [Phase 2 service contract](../phase-2/service-contract.md), [OpenAPI 3.2.1](../phase-2/openapi.yaml), and [proto3 service IDL](../../proto/ferrum/v1/service.proto).

## Context

The owner explicitly delegated the choice of detailed, previously unspecified Community service contracts to the technical architect. Existing ADRs already require HTTP/JSON plus gRPC, a shared authoritative security pipeline, native `/v1` versioning and transport-equivalent behavior. They do not enumerate every route, wire schema or error code.

## Decision

1. The HTTP surface is described by OpenAPI 3.2.1. The gRPC surface is proto3 under `ferrum.v1`.
2. Both transports serve the same canonical operation catalog, principal, tenant, resource/action, policy snapshot, rate-limit state and audit operation ID.
3. One TLS listener serves HTTP/JSON and gRPC with ALPN `h2` and `http/1.1`; default bind is loopback `127.0.0.1:8443`. Only TLS 1.3 is accepted; 0-RTT is disabled.
4. HTTP errors use RFC 9457 Problem Details. gRPC errors use canonical status codes plus a `google.rpc.Status` detail with the same stable error code and request ID.
5. The exact operations, HTTP paths, RPC names, shared request context, response fields, idempotency and compatibility rules are in the service contract and machine-readable artifacts. The AppRole API includes one-time Secret ID creation and immediate accessor-based revocation; idempotency replay receipts never expose the secret again.
6. Phase 2 does not include PKI, KV v2/leases, Transit, Raft/HA, a web UI, Vault-compatibility endpoints, OIDC, Kubernetes authentication or LDAP.

## Consequences

- Both transports must be tested against the same contract and every relevant negative authorization/seal/audit case.
- A protocol adapter may decode and encode only; all security decisions stay in the shared pipeline.
- Schema compatibility is checked in CI. Breaking changes require a new API version or an explicitly approved migration.
- The machine-readable contracts are design artifacts; they do not claim the server runtime exists.
- The API includes the complete AppRole Secret ID lifecycle (create once, revoke by accessor) and secret-safe replay receipt semantics.

## Verification

Lint OpenAPI and protobuf IDL; test generated bindings; compare operation and error semantics across transports; fuzz both parsers; and execute E2E tests against the actual TLS listener when Phase 2.1 is implemented.
