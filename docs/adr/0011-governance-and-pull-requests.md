# ADR-0011: Governance and pull-request workflow

- **Status:** Owner-approved.
- **Source decision:** Original Ferrum architecture ADR-0011, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community repository workflow.

## Decision

Changes to `main` go through pull requests and required CI checks. History remains linear; force-push is prohibited; merges use squash. Any emergency bypass must follow a documented, traceable procedure. Signed Git commits are not required at this stage and must not be introduced as a gate without a separate owner decision. Artifact signatures and release provenance are separate controls.

During solo-owner development in Phases 0–2, the owner may develop, review and approve their own changes. This is self-review, not independent peer review; no second account or reviewer is required during this period.

Before Phase 3, a qualified independent human reviewer must be designated for security-sensitive areas. The applicable ownership and repository rules must then be updated and verified. An independent external security audit remains a separate gate before a commercial MVP.

## Enforcement note

This ADR records the workflow decision. Actual GitHub enforcement is determined by the active Community ruleset and required checks, not by this document alone.
