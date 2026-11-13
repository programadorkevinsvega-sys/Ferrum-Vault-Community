# ADR-0023: CLI distribution

- **Status:** Owner-approved.
- **Source decision:** Community-applicable portion of original Ferrum architecture ADR-0023, baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community command-line client.

## Decision

Starting in Phase 2, provide tar.gz/zip archives for Linux x86_64 and aarch64, a universal macOS build and Windows x86_64.

Later distribution channels may include a Homebrew tap, winget or scoop, .deb/.rpm and an OCI image for the CLI.

Every release must provide verifiable checksums and signatures; SBOM and provenance follow the approved release pipeline. Publishing crates to crates.io requires a separate explicit owner decision and is not implied by CLI distribution.

Do not make `curl | sh` the default installation method. Provide reproducible installation instructions and verification steps before execution.

## Consequences

Every supported platform needs installation, update, signature, checksum and rollback tests before release.
