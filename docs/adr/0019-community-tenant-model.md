# ADR-0019: Community tenant model

- **Status:** Owner-approved.
- **Source decision:** Community portion of original Ferrum architecture ADR-0019, baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community data model and forward-compatible storage format.

## Decision

Community is single-tenant. Its reserved logical tenant identifier is `root`. Community isolation is provided through mounts and ACL; Community does not claim cryptographic isolation between tenants.

Reserve `tenant_id` in storage paths and authenticated additional data (AAD) from the first format version. In Community its value is always `root`. The identifier is bound using the fixed-order, length-prefixed AAD encoding in [ADR-0004](0004-barrier-encryption-aad-and-rotation.md).

## Security considerations

The tenant identity must be derived from authenticated and authorized server context. Never trust a freely client-controlled tenant field. Tests must cover mount/ACL boundaries, tenant substitution and attempts to reuse ciphertext under a different logical context.

## Consequences

Reserving the field now avoids a structural format migration if additional editions later need distinct tenant identifiers. This forward-compatibility provision does not add multi-tenant behavior to Community.
