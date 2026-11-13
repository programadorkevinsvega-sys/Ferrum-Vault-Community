# ADR-0007: Memory protection and unsafe boundary

- **Status:** Owner-approved.
- **Source decision:** Original Ferrum architecture ADR-0007, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community Rust workspace.

## Decision

`memguard` is the only crate permitted to contain narrowly isolated `unsafe` code. Its planned boundary includes memory locking (`mlock`), memory advice (`madvise`), core-dump restrictions and zeroization integration.

Every unsafe block must be isolated, justified and accompanied by safety documentation. Miri and applicable tests are required. All other crates must declare `#![forbid(unsafe_code)]`.

## Consequences and limitations

The public `memguard` API must be small and safe. Memory locking is best-effort and does not guarantee the absence of swap, copies or diagnostic disclosure. Platform-specific fallbacks and operating-system limitations must be documented; absolute memory protection must not be claimed.
