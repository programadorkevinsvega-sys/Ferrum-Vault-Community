# ADR-0008: Community and Enterprise boundary

- **Status:** Owner-approved.
- **Source decision:** Original Ferrum architecture ADR-0008, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Public edition boundary.

## Decision

Community is an independently buildable public edition. Enterprise is maintained separately and may consume Community crates through documented, versioned public traits and extension points. Community must not import, fetch or depend on Enterprise code, private packages, credentials or services.

The public repository contains only Community implementation, public interfaces and material approved for publication. Private implementation and confidential internal engineering material are not part of this repository.

## Consequences

Contract compatibility, versioning and integration tests are required at the edition boundary. Community must compile and operate without access to Enterprise or an Enterprise license. Packaging and API tests must ensure that private capabilities are not exposed accidentally.
