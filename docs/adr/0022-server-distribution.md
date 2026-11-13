# ADR-0022: Server distribution

- **Status:** Owner-approved.
- **Source decision:** Community-applicable portion of original Ferrum architecture ADR-0022, baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community server deployment artifacts.

## Decision

The primary server distribution is a distroless OCI image. Additional formats are a signed tarball for Linux x86_64/aarch64 and a hardened systemd unit.

The systemd baseline includes `NoNewPrivileges`, `ProtectSystem=strict`, `LimitCORE=0`, `CAP_IPC_LOCK` only where required, and an unprivileged service account.

The server must not run as root. A `curl | sh` installer is not the default installation method. macOS and Windows are not supported production server platforms.

Later package and orchestration formats may include .deb/.rpm, Helm and an operator when their roadmap phase is reached.

## Supply-chain requirements

Published artifacts include checksums, verifiable Sigstore/cosign signatures, CycloneDX SBOM and SLSA provenance. Each artifact format requires its own installation, update, rollback and hardening verification.
