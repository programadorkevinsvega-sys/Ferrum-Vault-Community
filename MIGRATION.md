# Community repository migration record

## Status

The curated public documentation foundation was merged into `main` through [PR #1](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/1) on 2026-11-13.

- Destination branch: `main`
- Initial snapshot merge commit: `184e100448258f0e4acf57e85c906b00bb17c235`
- Public files in the initial tree: 17

## Source reference

The private source snapshot reviewed for this migration was `programadorkevinsvega-sys/Ferrum-Vault`, branch `phase-0/foundations`, commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.

## Public selection

Created or curated for this repository:
- Public project overview and implementation status.
- High-level architecture principles and a summary of the Community/Enterprise boundary.
- Public roadmap without internal work breakdown or sensitive engineering detail.
- Contribution, security and license-status policies.
- Public-repository PR/issue templates, CI and complete-history Gitleaks scanning.
- A generic Markdown link/anchor validation script.
- Preventive ignore rules for environment files, private keys, keystores, recovery material, nested build outputs and test artifacts.

Not copied:
- Internal ADR collection.
- Full internal roadmap and phase acceptance criteria.
- STRIDE threat model, detailed data-protection design, security checklist and internal review procedure.
- Internal architecture and operational runbooks.
- Enterprise code or dependencies.
- Internal CI evidence, false-positive allowlists or source-repository workflow history.

The source snapshot contains no Rust implementation or Cargo manifests. Empty crate README placeholders were not published as Community implementation. The Community repository remains documentation-only.

## License

No `LICENSE` file is present on Community `main`. MPL-2.0 is tracked separately in [PR #4](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/4), which remains open and unmerged at the date of this record. The license proposal and any legal approval are outside this migration acceptance.

## History

This is a curated documentation snapshot, not a transfer of Git history, branches, tags, pull requests or workflow runs. No tags were present in the source or either destination at the time of comparison.

## Owner acceptance — 2026-11-13

The owner accepted this **Community documentation snapshot only**, after comparing the source repository, Enterprise and Community.

- The accepted Community `main` contains 17 tracked files. It is a public, curated subset, not a copy of the Enterprise tree.
- Current Community branch-tip trees were checked. No Enterprise ADRs, full STRIDE threat model, internal data-protection documents, operations runbooks, phase acceptance documents or Enterprise crate placeholders were found in those branch tips.
- The Community `.gitignore` security exclusions were restored from the reviewed source baseline in [PR #6](https://github.com/programadorkevinsvega-sys/Ferrum-Vault-Community/pull/6), merged after CI and Gitleaks passed.
- The active ruleset `Ferrum Vault Community — Protect main` applies to `refs/heads/main`. It requires a pull request and successful `Public repository quality gates` and `Gitleaks — all fetched Git history and refs` checks, with linear history, squash-only merges, no force-push and no branch deletion. It does not require a human approval.

This acceptance does **not** approve MPL-2.0, trademark clearance, production readiness, a Rust implementation, or transfer of source Git history.

## Source repository preservation

The original `programadorkevinsvega-sys/Ferrum-Vault` remains private, active and unarchived. Its `main` branch remains at `74a625ce4aa6c4d5dfba26212c18e5846cb42cf0`; `phase-0/foundations` remains at `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`, with source PR #1 still open. The owner has not authorized closing that PR, archiving or deleting the source repository, or transferring its history.
