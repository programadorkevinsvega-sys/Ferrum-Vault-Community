# ADR-0018: Optional compatibility with a Vault API subset

- **Status:** Owner-approved; legal review required before public announcement.
- **Source decision:** Public API-compatibility portion of original Ferrum architecture ADR-0018, baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Optional Community interoperability surface.

## Decision

Ferrum may offer compatibility with an explicitly documented subset of the HashiCorp Vault API: KV v2, Transit, basic PKI, AppRole and tokens. This is API interoperability only; it does not promise full product, behavior or security equivalence.

The compatibility surface is optional, versioned and implemented only after the native Ferrum API is stable. The work is planned for the delivery-ecosystem phase and may occur after the MVP.

Use only the descriptive phrase “compatible with a subset of the HashiCorp Vault API”. Do not use Vault as the product name, logo or visual identity. Any required non-affiliation notice is determined through legal review.

## Consequences

Maintain contract tests for every supported endpoint and document unsupported fields and behavioral differences. Compatibility must not weaken Ferrum authorization, isolation, audit or cryptographic controls. Complete legal review before announcing the compatibility feature.
