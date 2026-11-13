# ADR-0015: Reproducible builds and API versioning

- **Status:** Owner-approved.
- **Source decision:** Original Ferrum architecture ADR-0015, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community build and API lifecycle.

## Decision

The Rust workspace versions `Cargo.lock`, builds with `--locked` and pins its toolchain in `rust-toolchain.toml`. Release engineering requires reproducible-build verification, CycloneDX SBOM, artifact signatures using Sigstore and verifiable SLSA provenance.

Signed Git commits are not required at this stage. That choice is separate from artifact signing and provenance; it must not be interpreted as permission to omit release artifact controls.

The native API uses `/v1` routes, semantic versioning and a two-minor-version deprecation policy.

## Consequences

CI and release workflows must produce and verify the applicable reproducibility, SBOM, signature and provenance evidence before publishing artifacts. The policy does not claim those controls are implemented while the repository remains documentation-only.
