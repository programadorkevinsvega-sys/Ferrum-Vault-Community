# Source ADR classification and Community carryover

This matrix classifies the 24 decisions in the reviewed original Ferrum architecture baseline by product scope and records their treatment in the public edition.

**Source baseline:** `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`. The original private Enterprise repository retains the unabridged source decision set. Community publishes only the decisions required to design, build, test and distribute the public edition.

## Classification

- **Community:** applies to Community product behavior or its public engineering process.
- **Shared → Community adaptation:** applies across editions; the public ADR records the shared contract or Community behavior and omits private-edition detail.
- **Split by edition:** the original decision contains distinct edition-specific scopes; only the Community scope is public here.
- **Not a Community product ADR:** owner-only repository or organization administration, not a product architecture decision.

## Per-ADR mapping

| Source ADR | Scope classification | Community record | Carryover treatment |
|---|---|---|---|
| 0001 | Community | [ADR-0001](0001-workspace-scope.md) | Public crate/workspace boundaries for the initial phases. |
| 0002 | Community | [ADR-0002](0002-async-extension-contracts.md) | Public async extension and concurrency contract. |
| 0003 | Community | [ADR-0003](0003-storage-backend-contract.md) | Full Community storage contract and redb selection. |
| 0004 | Shared → Community adaptation | [ADR-0004](0004-barrier-encryption-aad-and-rotation.md) | Preserve AES-GCM, key hierarchy, canonical AAD and nonce safety; Community tenant is `root`. No private-edition tenant implementation is included. |
| 0005 | Community | [ADR-0005](0005-request-pipeline-and-fail-closed-audit.md) | Public service request order, audit sinks and fail-closed behavior. |
| 0006 | Shared → Community adaptation | [ADR-0006](0006-encrypted-raft-and-node-local-seal.md) | Preserve future Community HA design: openraft, ciphertext-only logs/snapshots, mTLS, explicit membership and node-local seal. |
| 0007 | Community | [ADR-0007](0007-memory-protection-and-unsafe-boundary.md) | Public unsafe boundary and memguard requirements. |
| 0008 | Shared edition boundary | [ADR-0008](0008-community-enterprise-boundary.md) | Publish dependency direction and independent-build requirement, not private implementation. |
| 0009 | Community/public governance | [ADR-0009](0009-public-documentation-language.md) | Public documentation and code-language policy. |
| 0010 | Shared engineering requirement | [ADR-0010](0010-testing-and-security-evidence.md) | Publish the test, coverage and evidence requirements applicable to Community. |
| 0011 | Community | [ADR-0011](0011-governance-and-pull-requests.md) | Publish the solo-owner workflow and future independent-review gate; actual GitHub enforcement is checked separately. |
| 0012 | Project-wide identity | [ADR-0012](0012-product-name-and-trademark-clearance.md) | Publish working product name and pending legal clearance. |
| 0013 | Community | [ADR-0013](0013-cryptography-and-key-management.md) | Publish Community crypto provider, AEAD and key-management contract. |
| 0014 | Community | [ADR-0014](0014-root-ceremony-recovery-and-backups.md) | Publish root ceremony, Shamir defaults, bootstrap and backup requirements; preserve pending quorum. |
| 0015 | Shared engineering/API policy | [ADR-0015](0015-reproducible-builds-and-api-versioning.md) | Publish build integrity and native API versioning rules. |
| 0016 | Community | [ADR-0016](0016-supported-platforms-and-toolchain.md) | Publish Community's Rust toolchain and supported platform policy. |
| 0017 | Split by edition | [ADR-0017](0017-community-license.md) | Publish only the Community MPL-2.0 declaration and its legal-review status. No private licensing terms are included. |
| 0018 | Community public compatibility scope | [ADR-0018](0018-vault-api-compatibility-subset.md) | Publish the optional API compatibility subset and pending legal review. |
| 0019 | Split by edition | [ADR-0019](0019-community-tenant-model.md) | Publish Community's single-tenant `root` model and reserved AAD/storage field. No private namespace implementation is included. |
| 0020 | Split by edition | [ADR-0020](0020-community-reliability-objectives.md) | Publish Community node-failure and snapshot-restore engineering targets. Private-edition regional DR details are omitted. |
| 0021 | Community | [ADR-0021](0021-user-interface.md) | Publish the deferred Community UI scope and browser-security constraints. |
| 0022 | Community | [ADR-0022](0022-server-distribution.md) | Publish server artifact and hardening policy. |
| 0023 | Community | [ADR-0023](0023-cli-distribution.md) | Publish CLI platform and distribution policy. |
| 0024 | Not a Community product ADR | Not published | Repository/organization administration and owner-only repository strategy do not define Community product behavior. The source decision remains in the private engineering record. |

## Pending values retained

The carryover does not resolve source decisions that were explicitly pending:

1. Exact numeric AES-GCM rotation threshold and quantitative safety margin.
2. Exact nonce-reservation block size.
3. Exact `generate-root` quorum.

External legal review for licensing, product naming and API-compatibility announcements also remains outstanding where identified in the corresponding ADRs.

## Integrity rule

A Community ADR may narrow a shared source decision to Community scope, but it must not contradict or silently change the approved source decision. Any future change requires an explicit superseding ADR and owner authorization. The public ADRs are design records, not implementation or security-validation evidence.
