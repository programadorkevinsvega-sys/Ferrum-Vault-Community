# Security policy

## Project status

Ferrum Vault Community is in early implementation, not a production secrets manager. The repository contains isolated cryptographic, offline recovery and process-local seal/bootstrap crates, but it does not yet contain a complete service, durable seal-state backend, server/API or CLI. The seal controller is volatile and is not restart-safe or multi-process. Do not use this project to store or process production secrets.

The project has not been independently audited and has no FIPS validation. Passing CI is not an external security audit or a production-readiness claim.

## Vulnerability reporting

A private vulnerability disclosure channel has not yet been published for this repository. Do not post exploit details, proof-of-concept code, credentials, keys, recovery material or other sensitive information in public issues or pull requests.

A confidential reporting process and response expectations must be configured and verified before the project is promoted for production use. No response-time or remediation commitment is made by this placeholder policy.

## Security claims and sensitive material

Security design statements describe intended or implemented scope only as supported by linked tests and CI evidence; they do not imply complete system security, cryptographic certification or production readiness.

Recovery shares, root material, bootstrap tokens and other secret fragments must never be committed to the repository, written to logs, placed in CI variables/artifacts/output, or included in fixtures and test corpora. Tests and fuzz targets must generate synthetic secret material at runtime and must not persist valid recovery fragments. An operation requiring a quorum must fail closed when its M-of-N policy is absent or invalid; no default quorum may be inferred from the separate Shamir recovery defaults. See [ADR-0014](docs/adr/0014-root-ceremony-recovery-and-backups.md) and the [seal lifecycle boundary](docs/security/seal-lifecycle.md).
