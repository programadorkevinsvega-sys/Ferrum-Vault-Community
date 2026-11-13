# Public decision summary: Community and Enterprise separation

This document summarizes the public repository boundary. It is not a copy of the internal Enterprise ADR collection.

## Approved repository roles

- `Ferrum-Vault-Community` is the public repository for approved Community code, public APIs, documentation and extension points.
- `Ferrum-Vault-Enterprise` is private and contains proprietary implementation and internal engineering materials.

## Dependency direction

Enterprise may consume documented and versioned Community interfaces. Community must never depend on Enterprise, import proprietary modules, or require private credentials or source access to build.

## Publication rules

Do not publish the following in Community:

- Enterprise implementation or proprietary dependencies.
- Internal architecture decision records or the complete internal roadmap.
- Full internal threat models, security reviews or operational runbooks.
- Confidential engineering discussions, credentials, keys or customer information.

Every public contribution and release must be checked for accidental disclosure, licensing status, dependency scope and references to private resources.

## License

MPL-2.0 is proposed for Community but remains subject to legal review. No license file is published yet; see [License status](../../LICENSE-STATUS.md).
