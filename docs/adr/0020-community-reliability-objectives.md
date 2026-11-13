# ADR-0020: Community reliability objectives

- **Status:** Owner-approved as engineering targets, not contractual SLAs.
- **Source decision:** Community-applicable portion of original Ferrum architecture ADR-0020, baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Future Community high-availability and snapshot recovery work.

## Decision

The following are engineering targets for the relevant implementation phase:

- **Node failure:** in a 3- or 5-node cluster, RPO 0 for operations committed by quorum and automatic leader-election RTO of 30 seconds or less.
- **Snapshot restore:** snapshots every 5 minutes, RPO of 5 minutes or less, and RTO of 1 hour or less for a 10 GB data set.

## Conditions

These are targets, not commercial guarantees or demonstrated capabilities. They require automated tests under failure, load and recovery. Each test records data size, hardware, latency, topology and network limits. Any deviation is documented with evidence and owner acceptance.

## Consequences

Do not publish compliance claims based only on configuration, design documents or isolated benchmarks. The objectives apply only when the corresponding Community HA/recovery capability is implemented and tested.
