# ADR-0001: Workspace scope and architecture boundaries

- **Status:** Owner-approved.
- **Source decision:** Original Ferrum architecture ADR-0001, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Public Ferrum Community edition.

## Context

The workspace must grow by phase and avoid premature components. Community must remain independently buildable and must not require private source, credentials, packages or runtime services.

## Decision

The planned Phase 0–2 crates are `core`, `crypto`, `memguard`, `seal`, `storage`, `storage-redb`, `audit`, `auth`, `policy`, `api`, `server` and `cli`. Later-phase components remain in the roadmap until their phase. No crate is added ahead of its phase without an owner-approved decision.

Only `memguard` may contain narrowly scoped `unsafe` code. Every other crate must use `#![forbid(unsafe_code)]`.

## Consequences

The current repository may contain documented crate placeholders before it contains Cargo manifests or runtime code. Enterprise-only implementation is not part of this workspace. This ADR describes the approved structure, not implemented functionality or a security validation.
