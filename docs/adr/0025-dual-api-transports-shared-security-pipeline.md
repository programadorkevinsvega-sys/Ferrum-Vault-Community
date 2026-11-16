# ADR-0025: Dual native API transports with a shared security pipeline

- **Status:** Owner-approved on 2026-11-15.
- **Scope:** Ferrum Vault Community Phase 2 native service API.
- **Decision authority:** Explicit owner selection for Phase 2.0, D2.0-01.
- **Related decisions:** [ADR-0002](0002-async-extension-contracts.md), [ADR-0005](0005-request-pipeline-and-fail-closed-audit.md), [ADR-0015](0015-reproducible-builds-and-api-versioning.md), [ADR-0019](0019-community-tenant-model.md), [ADR-0024](0024-unsealer-port-and-optional-aws-kms.md).

## Context

Phase 2 needs a native API surface for Community. ADR-0005 already defines the required request-pipeline order and includes an HTTP/gRPC server boundary. ADR-0015 establishes the native `/v1` route namespace, semantic versioning and the two-minor-version deprecation policy. Those ADRs do not, by themselves, settle whether the MVP exposes one or both transports.

## Decision

The Community Phase 2 MVP exposes **both**:

1. **HTTP with JSON request/response representations**, using the native `/v1` API namespace required by ADR-0015.
2. **gRPC** as a second native API transport.

Both transports must enter the **same authoritative security pipeline** and share the same logical request/security context. Transport adapters may perform protocol-specific decoding and response encoding, but they must not implement independent or weaker copies of authentication, rate limiting, seal-state gating, canonicalization, authorization or audit enforcement.

For either transport, the security pipeline preserves the ADR-0005 order:

1. TLS 1.3 listener using rustls.
2. HTTP/gRPC server integration and server-generated request ID.
3. Request size and time limits.
4. IP-based pre-authentication rate limiting.
5. Local seal-state check.
6. Authentication.
7. Identity-based rate limiting.
8. Canonical route/action and ACL evaluation.
9. Approved operation handler.
10. Durable audit before and after sensitive operations.

The two transports represent access paths to the same approved native operations. They do not create separate identities, authorization models, seal-state semantics, tenant contexts, rate-limit policy or audit guarantees. A control failure on either transport must fail closed under the same approved rules.

Community remains single-tenant. The logical tenant identifier is `root` and is derived from trusted server-side authenticated/authorized context; neither transport may accept a client-controlled tenant override.

## Consequences

- Phase 2 implementation and acceptance must exercise both transports against the same operation catalog and shared security invariants.
- Tests must prove that an operation denied through one transport cannot be reached through the other by changing protocol, route representation or method mapping.
- Rate limiting, authorization, audit and sealed-mode policy must have equivalent security semantics across HTTP/JSON and gRPC.
- The HTTP API follows the existing `/v1`, semantic-versioning and deprecation requirements in ADR-0015.
- The optional Vault API compatibility subset in ADR-0018 remains separate and later; it is not implied by this decision.
- This decision does not approve a route catalog, RPC method names, wire schema technology, gRPC IDL, server framework, listener topology, certificate provisioning or numerical resource limits.

## Decisions still open

The following remain subject to separate owner approval before dependent implementation:

- HTTP server and gRPC server/framework selection, listener topology and whether listeners are shared or separate.
- The schema/source-of-truth and code-generation strategy for HTTP/JSON contracts.
- The gRPC IDL and serialization/schema tooling.
- Mapping of operation names, typed errors, status codes and validation failures between transports.
- Whether each selected operation is exposed through both transports or has an explicitly documented transport-specific exclusion.
- Transport-specific resource limits and their shared policy semantics; numeric values remain pending.
- TLS certificate provisioning, trust roots, rotation and reload behavior.

A decision may be deferred only if the dependent operation/feature is disabled and the exclusion is explicit. No transport may provide a bypass or permissive fallback.

## Required verification

- Contract tests establish equivalent operation semantics and error classifications across both transports.
- Integration tests call the same protected operation through HTTP/JSON and gRPC and verify identical authentication, rate-limit, seal-state, canonicalization, ACL and audit behavior.
- Negative security tests prove that malformed/expired/revoked credentials, denied ACL decisions, sealed-state restrictions, request limits and audit-sink failures block both transports consistently.
- Cross-transport tests attempt to bypass denial by changing protocol, route/method encoding, canonical resource or request metadata.
- Fuzzing covers each untrusted protocol/schema/parser boundary introduced by the selected implementations; only synthetic credentials and data are used.
- E2E acceptance traverses the actual TLS listener(s) for both transports.

These tests are implemented in the relevant Phase 2 subphases. Passing the ADR review or CI does not itself establish runtime implementation, production readiness, FIPS validation or independent security audit.
