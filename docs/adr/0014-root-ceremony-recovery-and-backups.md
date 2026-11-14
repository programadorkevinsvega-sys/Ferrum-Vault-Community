# ADR-0014: Root ceremony, recovery and backups

- **Status:** Owner-approved; exact generate-root M/N values and operation scope remain pending.
- **Source decision:** Original Ferrum architecture ADR-0014, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community root-key custody and recovery.

## Decision

Root material is created through an offline ceremony with m-of-n custodians, isolated equipment and a recorded procedure. Shamir defaults to 5 shares with a threshold of 3; both values are configurable. The service never stores recovery shares.

Bootstrap uses a one-time token. The `generate-root` workflow requires a quorum, but the exact quorum number remains pending. Recovery material must be shown only as required by the ceremony and must never enter logs, fixtures or service storage.

Durations and leases use a monotonic clock. Certificate validity uses wall-clock time. Clock-drift tolerance and NTP alert behavior must be defined and tested during the relevant implementation phase.

Backups use an encryption key independent from the live data-key hierarchy. Authenticate backup manifests and verify integrity and environment binding before restore.

## Consequences

Ceremony, abuse-case, backup and recovery runbooks and tests are required in their implementation phases. This record describes approved design, not an implemented recovery capability.


## Implementation observations and explicit constraints (Phase 1.4)

The Phase 1.4 process-local implementation binds bootstrap and unseal to the authenticated FRS1 ceremony identifier, verifies reconstruction integrity, and does not retain recovery shares in the controller. The 5 shares / threshold 3 setting described above is the recovery-crate default; it is not approval to use 3-of-5 for `generate-root`, rotation or revocation.

The owner has reaffirmed these constraints for any quorum-protected operation:

- No recovery fragment, root material or bootstrap credential may be written to the repository, logs, CI output, CI variables or CI artifacts. Tests/fuzzers must generate synthetic material at runtime.
- The operation fails closed if its M-of-N quorum is absent, invalid or not configured. There is no fallback or inferred default.
- A configured quorum must reject fewer than M distinct valid fragments, accept M valid distinct fragments from the same ceremony, and reject duplicate or corrupted fragments.
- The exact numeric M and N, and whether the same quorum applies to rotation, revocation, or neither, are not yet specified in the owner's message because the values/scope remain placeholders. No implementation may infer them from the 5/3 recovery default.

These constraints do not alter the existing offline custody model. They do not by themselves define `generate-root` semantics, fragment format, root replacement/rotation procedure or revocation semantics; those details must be specified before those operations are implemented.
