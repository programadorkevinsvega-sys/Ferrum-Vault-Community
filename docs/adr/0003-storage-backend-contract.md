# ADR-0003: Storage backend contract

- **Status:** Owner-approved.
- **Source decision:** Original Ferrum architecture ADR-0003, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community storage abstractions and initial backend.

## Decision

The backend contract provides:

- `get`, `put` and `delete`;
- paginated `list(prefix, limit, cursor)`;
- atomic `txn(batch, preconditions)`; and
- compare-and-swap (CAS) conditional on an expected version or absence.

The contract specifies linearizable behavior, limits, cursor semantics, conflicts, isolation, durability and typed errors. The initial backend for Phases 1–2 is `redb`. RocksDB is not selected; reconsideration is deferred until comparative benchmarks in Phase 6.

## Security considerations

Protected values are encrypted before reaching this layer; the backend receives ciphertext and required non-secret metadata only. Each adapter must pass the shared conformance suite. An operation that does not meet atomicity or linearizability requirements must not claim those guarantees.
