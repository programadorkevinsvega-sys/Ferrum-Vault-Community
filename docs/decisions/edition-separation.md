# Public decision summary: Community and Enterprise separation

This document summarizes the public edition boundary. The detailed public Community decisions are indexed in [Community ADRs](../adr/README.md).

## Approved repository roles

- **Ferrum-Vault-Community:** public edition containing approved Community code, APIs, documentation, tests and extension points.
- **Ferrum-Vault-Enterprise:** a separate private edition. Its proprietary implementation and private engineering material are not part of this repository.

## Dependency direction

Enterprise may consume documented and versioned Community interfaces. Community must never depend on Enterprise, import proprietary modules, or require private credentials or source access to build or operate.

## Publication rules

Do not publish proprietary implementation, private dependencies, confidential internal engineering materials, credentials, keys, recovery shares or customer information in Community. Adapt shared decisions to the public Community scope rather than copying private-only detail.

## Community license

Community is provisionally published under the **Mozilla Public License 2.0 (MPL-2.0)**. The unmodified license text is in the root [LICENSE](../../LICENSE). This is an operative public license declaration for covered software with the required notice; provisional status means qualified legal review remains pending. See [LICENSE-STATUS.md](../../LICENSE-STATUS.md).
