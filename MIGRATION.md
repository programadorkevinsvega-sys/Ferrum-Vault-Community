# Community documentation migration record

## Current record

The initial curated documentation snapshot was merged into Community `main` through [PR #1](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/1) on 2026-11-13. Subsequent public documentation and licensing updates were merged separately.

- Current Community default branch: `main`.
- This migration record tracks public documentation provenance; it is not a transfer of source Git history.
- The initial snapshot contained 17 public files. The current repository has grown through reviewed documentation and policy changes.

## Source baseline reviewed

The source architecture baseline was `programadorkevinsvega-sys/Ferrum-Vault`, `phase-0/foundations`, commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`. The source `main` tip `b79b0d4f8111b85370da473615f5a16806047061` was compared with that branch: both trees contained the same 62 tracked file paths and identical file contents.

The source snapshot is documentation-only. It contains planned crate README placeholders but no Cargo manifests or Rust implementation.

## Public ADR carryover

The initial curated migration intentionally omitted internal ADRs. That left Community without a complete public record of the owner-approved decisions governing its own product.

This documentation update corrects that gap:

- Public Community ADRs 0001–0023 preserve the source decision identifiers and statuses.
- Each public ADR records its source decision ID and the reviewed baseline commit.
- Decisions applicable to both editions are adapted to Community scope only.
- Private-edition implementation detail and owner-only repository administration are not reproduced.
- The unabridged internal decision records remain in the private engineering repository; this public directory is sufficient to understand and implement the Community edition without consulting private documents.
- Pending parameters remain explicitly pending. This migration does not approve a numeric AES-GCM rotation threshold, nonce-reservation block size or generate-root quorum.

The public records are English-language adaptations for Community, not a transfer of the original ADR files or Git history.

## Public selection and exclusions

Community includes its public product scope, approved interfaces, architecture, security requirements, contribution and release policies, and roadmap. It does not include proprietary implementation, confidential internal material, private runbooks or private-only edition design. No source branches, tags, pull requests, commits or workflow runs were migrated.

## License status

The [MPL-2.0 license](LICENSE) was added and merged through [PR #4](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/4). It is the operative provisional license declaration for covered Community materials carrying the required notices. “Provisional” means qualified legal review is pending; it does not make the license text non-binding or alter its terms. See [LICENSE-STATUS.md](LICENSE-STATUS.md). No claim is made that legal review is complete.

## Source repository preservation

The original Ferrum-Vault source repository remains private and is not replaced by Community. This migration did not delete, archive, rename or transfer that repository, and it did not transfer its Git history.
