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


## Phase 1.7 implementation record

The Community adapter is implemented in `crates/storage` as `ferrum-storage`, using the redb version pinned in the workspace. It opens the database in multi-writer mode and requests immediate durability for all write transactions. The conformance tests cover versioned CRUD, expected-version/absence preconditions, atomic batches, prefix pagination and cursor binding. Deletes write durable versioned tombstones, hidden from reads/listing, so recreating a deleted key cannot reuse an old CAS version (ABA resistance).

The same adapter implements the Phase 1.6 `NonceUsageLedger`, `RotationStore` and `KeyDependencyInventory` contracts. High-water reservations persist the immutable caller-supplied policy before returning and reject a complete block that crosses the configured rotation threshold without advancing the persisted high-water mark; rotation CAS plus audit and checkpoint plus audit each share one transaction. FBE1 live-record dependency updates are atomic with record writes. Generic KV writes reject FBE1 envelope magic, and the one-time migration scan marks the inventory incomplete if legacy FBE1 values are found in generic KV; reconciliation fails until those values are moved or removed. Backup, snapshot and in-progress rotation-job references are explicit durable registrations. Key retirement remains fail-closed until a complete external reconciliation is recorded. An empty-inventory result atomically establishes a durable per-key-version retirement fence; later FBE1 writes and external dependency registrations for that version are rejected in their own writer transactions, serializing creation against retirement. Rotation `Started`/`Checkpointed` events register the target key version as a job dependency alongside the checkpoint and audit event; `Completed` releases it atomically.

The tests verify reopen/recovery behavior, concurrent disjoint reservations through independent database handles and eight separate OS processes, rollback of an uncommitted transaction, tombstone-based CAS version monotonicity, cursor properties and rotation persistence. They are not destructive power-loss tests across every target filesystem. Deployment-specific backup/restore and device durability validation remain operational acceptance work.
