# ADR-0014: Root ceremony, recovery and backups

- **Status:** Owner-approved; root-operation quorum is explicitly 2-of-3 for generate-root, root rotation and root revocation.
- **Source decision:** Original Ferrum architecture ADR-0014, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community root-key custody and recovery.

## Decision

Root material is created through an offline ceremony with m-of-n custodians, isolated equipment and a recorded procedure. Shamir defaults to 5 shares with a threshold of 3; both values are configurable. The service never stores recovery shares.

Bootstrap uses a one-time token. `generate-root`, root rotation and root revocation require an explicitly configured 2-of-3 root quorum. An absent or invalid policy fails closed; there is no default or fallback. The general Shamir recovery library retains its independent 5-of-3 default, which must not be substituted for the root-operation policy. Recovery fragments must be handled only through the out-of-band custodian ceremony and must never enter source control, logs, fixtures, CI output, CI variables or CI artifacts. Revocation of derived credentials does not require root quorum but must be written to the audit sink.

Durations and leases use a monotonic clock. Certificate validity uses wall-clock time. Clock-drift tolerance and NTP alert behavior must be defined and tested during the relevant implementation phase.

Backups use an encryption key independent from the live data-key hierarchy. Authenticate backup manifests and verify integrity and environment binding before restore.

## Consequences

Ceremony, abuse-case, backup and recovery runbooks and tests are required in their implementation phases. This record describes approved design, not an implemented recovery capability.


## Implementation observations and explicit constraints (Phase 1.4)

The Phase 1.4 process-local implementation binds bootstrap and unseal to the authenticated FRS1 ceremony identifier, verifies reconstruction integrity, and does not retain recovery shares in the controller. The recovery crate retains its general 5 shares / threshold 3 default. The root-operation policy is a separate, explicit 2-of-3 configuration; the root FRS1 set used by `ferrum-seal` must match the configured root policy exactly.

The owner has approved a fixed 2-of-3 quorum for `generate-root`, root rotation and root revocation. Derived-credential revocation does not require this quorum but must be audited.

- The policy is configured explicitly with M=2 and N=3; no default or fallback is installed by `SealController::new()`.
- Missing configuration and invalid values (M < 2 or M > N) fail closed.
- The FRS1 set bound to the root controller must match the explicit 2-of-3 policy. Fewer than two fragments fail; two or three distinct valid fragments from the same ceremony are accepted. Duplicate participant IDs, corrupt share payloads and shares from another ceremony/set are rejected.
- The general recovery library's 5-of-3 default remains separate and cannot be silently reused as root-operation quorum.
- Root fragments, root material and bootstrap tokens must never be written to the repository, logs, CI output, CI variables or CI artifacts. Unit tests and fuzz targets generate synthetic material at runtime only.
- The quorum gate supplies an operation-specific context to a caller-owned callback; it does not retain or expose fragment bytes. Durable root mutation and audit transactions require the later service/storage integrations.

The credential-revocation helper accepts no root fragments and has no root-quorum dependency. It requires a caller-provided audit sink to accept a request event before invoking the revocation callback and records the result using only a domain-separated credential-reference fingerprint, never the raw identifier. If the audit sink cannot accept the request event, the revocation callback is not run.


## Phase 1.5 unsealing clarification

The mandatory default Unsealer adapter for the seal lifecycle is Shamir 2-of-3. This does not change the generic offline recovery library's independent 5-of-3 default. The optional AWS KMS adapter is explicitly selected, disabled by default and never silently substituted when Shamir or KMS fails. KMS Decrypt permission allows unseal without presenting Shamir shares, so it is a high-impact trust privilege. It does not bypass the separately configured 2-of-3 quorum for `generate-root`, root rotation or root revocation. See ADR-0024.
