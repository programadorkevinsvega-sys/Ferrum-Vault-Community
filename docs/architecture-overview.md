# Architecture overview

## Purpose

Ferrum Vault is planned as a Rust-based platform for secrets management, encryption services and public-key infrastructure.

## Community design principles

- **Independent edition:** Community must build and operate without access to the private Enterprise repository.
- **Clear public contracts:** public APIs and extension points will be documented, versioned and tested for compatibility.
- **Secure engineering:** security-sensitive behavior must be supported by implementation, tests and review; project documentation alone is not evidence of security.
- **Reviewed cryptography:** the project intends to use established cryptographic libraries and avoid custom cryptographic algorithms.
- **Least privilege:** authorization should deny by default and grant only the access required for an operation.
- **Auditable operations:** sensitive operations should be designed with explicit auditability and failure behavior.
- **Transparent status:** planned behavior must be distinguished from implemented and independently verified behavior.

## Edition boundary

Community contains only public code, public APIs, documentation and approved extension points. Proprietary implementation and complete internal design/security material belong to the private Enterprise repository. Community must never import, fetch or depend on Enterprise-only code.

## Current implementation status

The accepted Phase 1 implementation in `main` contains four library crates: `ferrum-crypto` (AWS-LC provider, key-management contract and barrier/AAD/rotation contracts), `ferrum-recovery` (offline Shamir recovery primitives), `ferrum-seal` (seal/bootstrap lifecycle, root-operation quorum and provider-neutral Unsealer, with an optional disabled-by-default AWS KMS adapter), and `ferrum-storage` (durable redb adapters for versioned KV, nonce reservations, rotation state/audit and key-dependency inventory). Exact implementation and CI evidence is recorded in [ROADMAP.md](../ROADMAP.md) and the relevant PRs.

These are library-level components and contracts; Community does not yet contain their complete service composition, a running native server/API, authentication and ACL pipeline, or CLI. That integration is planned for Phase 2 and later phases. The seal controller and durable storage backend must not be described as an already integrated, restart-safe server lifecycle. The project is not production-ready, independently audited or FIPS validated.
