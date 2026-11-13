# Community Architecture Decision Records

This directory contains the public, Community-scoped adaptations of the owner's approved Ferrum architecture decisions. They preserve the source decision identifiers and status while omitting private-edition implementation details and owner-only repository administration.

See the [source ADR classification and carryover matrix](SOURCE-MAP.md) for the per-decision edition/scope classification and the reason each original ADR was published, adapted or withheld.

## Decision status

- **Owner-approved:** the owner approved the architecture decision in the source baseline.
- **Accepted requirement:** the source baseline records the requirement as accepted; this label is preserved rather than upgraded.
- **Pending:** an explicit parameter or external review remains unresolved. A pending detail does not invalidate the approved parts of its decision.
- **Superseded:** replaced by a later public ADR (none at this baseline).

These records describe approved design, not implemented or independently verified behavior.

## Provenance

The public records below adapt the corresponding source ADRs from the owner-approved Ferrum architecture baseline, commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`. The source `main` tip was compared with `phase-0/foundations`; both contained the same 62 tracked file paths and identical file contents. The source decision identifiers and approved/pending status are preserved.

The adaptations are written in English for public documentation. Decisions with both Community and private-edition implications are limited here to the Community behavior and public interface. Private-only details are not reproduced. Repository/organization administration decisions that do not define Community product behavior are not published as product ADRs.

## Index

| Public ADR | Source ADR | Topic | Status |
|---|---:|---|---|
| [0001](0001-workspace-scope.md) | 0001 | Workspace scope and architecture boundaries | Owner-approved |
| [0002](0002-async-extension-contracts.md) | 0002 | Async extension contracts | Owner-approved |
| [0003](0003-storage-backend-contract.md) | 0003 | Storage backend contract | Owner-approved |
| [0004](0004-barrier-encryption-aad-and-rotation.md) | 0004 | Barrier encryption, AAD and rotation | Owner-approved; numeric parameters pending |
| [0005](0005-request-pipeline-and-fail-closed-audit.md) | 0005 | Request pipeline and fail-closed audit | Owner-approved |
| [0006](0006-encrypted-raft-and-node-local-seal.md) | 0006 | Encrypted Raft and node-local seal | Owner-approved; implementation deferred |
| [0007](0007-memory-protection-and-unsafe-boundary.md) | 0007 | Memory protection and unsafe boundary | Owner-approved |
| [0008](0008-community-enterprise-boundary.md) | 0008 | Community and Enterprise boundary | Owner-approved |
| [0009](0009-public-documentation-language.md) | 0009 | Public documentation language | Owner-approved |
| [0010](0010-testing-and-security-evidence.md) | 0010 | Testing strategy and security evidence | Accepted requirement |
| [0011](0011-governance-and-pull-requests.md) | 0011 | Governance and pull requests | Owner-approved |
| [0012](0012-product-name-and-trademark-clearance.md) | 0012 | Product name and trademark clearance | Working name approved; legal clearance pending |
| [0013](0013-cryptography-and-key-management.md) | 0013 | Cryptography and key management | Owner-approved; rotation threshold pending |
| [0014](0014-root-ceremony-recovery-and-backups.md) | 0014 | Root ceremony, recovery and backups | Owner-approved; generate-root quorum pending |
| [0015](0015-reproducible-builds-and-api-versioning.md) | 0015 | Reproducible builds and API versioning | Owner-approved |
| [0016](0016-supported-platforms-and-toolchain.md) | 0016 | Supported platforms and toolchain | Owner-approved |
| [0017](0017-community-license.md) | 0017 | Community license | Owner-approved; legal review pending |
| [0018](0018-vault-api-compatibility-subset.md) | 0018 | Optional API compatibility subset | Owner-approved; legal review pending |
| [0019](0019-community-tenant-model.md) | 0019 | Community tenant model | Owner-approved |
| [0020](0020-community-reliability-objectives.md) | 0020 | Community reliability objectives | Approved engineering targets; not SLAs |
| [0021](0021-user-interface.md) | 0021 | User interface | Owner-approved; implementation deferred |
| [0022](0022-server-distribution.md) | 0022 | Server distribution | Owner-approved |
| [0023](0023-cli-distribution.md) | 0023 | CLI distribution | Owner-approved |

## Change control

Do not silently change an approved decision or resolve a pending parameter by assumption. A change requires a new or superseding ADR with rationale, impact and owner authorization. Keep public ADRs aligned with the Community roadmap and implementation. A passing CI run does not establish implementation, independent review or external certification.
