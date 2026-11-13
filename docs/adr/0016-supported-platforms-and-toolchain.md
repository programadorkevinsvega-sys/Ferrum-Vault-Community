# ADR-0016: Supported platforms and Rust toolchain

- **Status:** Owner-approved.
- **Source decision:** Original Ferrum architecture ADR-0016, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community server, CLI and development platform policy.

## Decision

The minimum supported Rust version (MSRV) tracks the stable release from two releases earlier. The project pins the selected toolchain in `rust-toolchain.toml` and reviews it periodically.

The production server targets Linux x86_64 and aarch64. CLI use and development support macOS and Windows. The primary server container format is a distroless OCI image.

## Consequences

CI must test the approved platform matrix as implementation is added. Server support on macOS or Windows must not be implied.
