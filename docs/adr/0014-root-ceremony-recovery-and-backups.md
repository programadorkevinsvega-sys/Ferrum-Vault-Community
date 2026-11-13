# ADR-0014: Root ceremony, recovery and backups

- **Status:** Owner-approved; exact generate-root quorum remains pending.
- **Source decision:** Original Ferrum architecture ADR-0014, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community root-key custody and recovery.

## Decision

Root material is created through an offline ceremony with m-of-n custodians, isolated equipment and a recorded procedure. Shamir defaults to 5 shares with a threshold of 3; both values are configurable. The service never stores recovery shares.

Bootstrap uses a one-time token. The `generate-root` workflow requires a quorum, but the exact quorum number remains pending. Recovery material must be shown only as required by the ceremony and must never enter logs, fixtures or service storage.

Durations and leases use a monotonic clock. Certificate validity uses wall-clock time. Clock-drift tolerance and NTP alert behavior must be defined and tested during the relevant implementation phase.

Backups use an encryption key independent from the live data-key hierarchy. Authenticate backup manifests and verify integrity and environment binding before restore.

## Consequences

Ceremony, abuse-case, backup and recovery runbooks and tests are required in their implementation phases. This record describes approved design, not an implemented recovery capability.
