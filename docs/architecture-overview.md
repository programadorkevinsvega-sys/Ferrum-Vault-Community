# Architecture overview

## Purpose

Ferrum Vault is a Rust-based platform for secrets management, encryption services and public-key infrastructure. The Community edition is developed as an independently buildable public product with documented, versioned contracts.

## Community design principles

- **Independent edition:** Community must build and operate without access to the private Enterprise repository.
- **Clear public contracts:** public APIs and extension points are documented, versioned and tested for compatibility.
- **Secure engineering:** security-sensitive behavior must be supported by implementation, tests and review; project documentation alone is not evidence of security.
- **Reviewed cryptography:** use established cryptographic libraries and avoid custom cryptographic algorithms.
- **Least privilege:** authorization denies by default and grants only the access required for an operation.
- **Auditable operations:** sensitive operations require explicit auditability and fail-closed behavior.
- **Transparent status:** planned behavior is distinguished from implemented and independently verified behavior.

## Edition boundary

Community contains only public code, public APIs, documentation and approved extension points. Proprietary implementation and complete internal design/security material belong to the private Enterprise repository. Community must never import, fetch or depend on Enterprise-only code, credentials, private packages or services. See [ADR-0008](adr/0008-community-enterprise-boundary.md).

## Implemented foundation: Phase 1

The Phase 1.1–1.7 library foundation is complete, integrated into Community main and owner-accepted. It includes:

- AWS-LC cryptographic provider and the key-management provider boundary.
- Offline Shamir recovery primitives and ceremony procedures.
- Seal/bootstrap and quorum controls, with the mandatory Shamir 2-of-3 Unsealer and optional AWS KMS adapter disabled by default.
- Barrier encryption, canonical AAD, FBE1 envelopes, nonce-budget contracts and resumable key rotation.
- Durable redb storage contracts and adapters, including versioned operations, atomic batches, nonce reservations, rotation checkpoints/audit coupling and key-dependency retirement fences.

These components are libraries and contracts, not yet a composed network service. Their boundaries and residual limitations remain documented in the corresponding ADRs and Phase 1 roadmap evidence.

## Planned service: Phase 2

Phase 2 defines the native versioned /v1 HTTP/JSON API and a gRPC transport, both entering one shared TLS 1.3/rustls request pipeline, authentication, deny-by-default authorization and durable fail-closed audit. This dual-transport choice is approved in [ADR-0025](adr/0025-dual-api-transports-shared-security-pipeline.md). The request ordering and non-negotiable security invariants are defined in [ADR-0005](adr/0005-request-pipeline-and-fail-closed-audit.md); the API lifecycle is defined in [ADR-0015](adr/0015-reproducible-builds-and-api-versioning.md).

The first Phase 2 subphase, 2.0, consolidates the already owner-approved architecture and records detailed Community implementation defaults selected under the owner's explicit technical delegation on 2026-11-16. Existing decisions remain binding; the new low-level selections are not misattributed to the original source baseline. The [Phase 2.0 decision register](phase-2/decision-register.md), [approved design carryover](phase-2/approved-design-carryover.md), [service contract](phase-2/service-contract.md), [configuration contract](phase-2/configuration-contract.md), [OpenAPI contract](phase-2/openapi.yaml), [proto3 IDL](../proto/ferrum/v1/service.proto), and ADRs 0026–0029 now define the operation catalog, wire/error semantics, credentials, ACL grammar, resource limits, sealed-mode allowlist, TLS/configuration and durable audit/outbox behavior. Phase 2.0 remains a documentation/contract gate until validation passes and the owner accepts the phase report. No Phase 2 server/API runtime is claimed before implementation and acceptance.

The project MVP does not include a web UI. A future administrative UI will use the same server/API and will not replace server-side authentication, authorization, resource limits or audit; see [ADR-0021](adr/0021-user-interface.md).

## Product and production status

The Community project is not production-ready. Passing CI, completing Phase 1 or documenting Phase 2 does not authorize production use. The project has not been independently security-audited and has no FIPS validation. Production promotion remains subject to the roadmap's security, operational, legal and release gates.
