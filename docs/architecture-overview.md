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

This repository is currently documentation-only. It has no Cargo manifests, Rust implementation, server, CLI or production release. The principles above are design goals, not claims about working software.
