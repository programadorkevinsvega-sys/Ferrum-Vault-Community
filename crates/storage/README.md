# ferrum-storage

The Community storage crate implements ADR-0003 using redb as the initial durable backend.

## Contract

`KvBackend` exposes versioned `get`, `put`, `delete`, prefix `list` with opaque cursors, compare-and-swap and atomic mutation batches guarded by expected-version or absence preconditions. Limits and malformed cursors are reported through typed errors. Deletes retain an internal versioned tombstone: reads and pagination treat the key as absent, while a later recreation increments its version instead of resetting it and reopening an ABA window.

`RedbStore` opens the database in `MultiWriter` mode and explicitly requests `Durability::Immediate` for every write transaction. The same database implements the Phase 1.6 `NonceUsageLedger`, `RotationStore` and `KeyDependencyInventory` contracts. Multi-process safety is exercised by child-process tests that open independent `RedbStore` handles to the same file and verify disjoint nonce reservations.

## Encryption boundary

The generic key/value methods persist opaque bytes. Callers must encrypt protected plaintext with `ferrum-crypto::barrier::BarrierCipher` before storing it. Generic KV writes reject the reserved `FBE1` envelope magic, including batch mutations. Use `put_encrypted` and `delete_encrypted` for FBE1 records so the live-key dependency index is updated atomically with the ciphertext record. FBE1 paths are subject to the same 4,096-byte key limit as generic KV keys. On open, a one-time migration scan detects legacy FBE1 values already placed in generic KV and keeps key retirement fail-closed until those records are moved or removed and the inventory is reconciled.

## Nonce and key lifecycle

The nonce ledger persists the high-water reservation and caller-supplied policy in one immediate-durability transaction before returning a reservation. Policy is immutable for each `(key_id, key_version)`. It refuses the entire next block before committing if the block would cross the configured rotation threshold, so repeated requests cannot burn additional counter ranges after rotation is required. This crate does not select a nonce block size or AES-GCM rotation threshold; ADR-0004's owner-pending parameters remain explicit caller inputs.

The dependency inventory tracks live FBE1 records and explicit backup, snapshot and in-progress rotation-job registrations. Fresh and upgraded stores start with an incomplete inventory. Key retirement checks fail closed until the operator has reconciled the complete external inventory and explicitly calls `confirm_inventory_reconciled`; an empty local table is not evidence that external backups or snapshots do not exist. An `Ok(false)` result from `has_dependencies` atomically writes a durable retirement fence for that key version; FBE1 writes and new backup/snapshot/job registrations check the fence in their own write transactions. Rotation `Started`/`Checkpointed` events automatically register the target key as a job dependency with the checkpoint and audit event; `Completed` releases it in that same transaction. Thus a dependency either commits before the fence and blocks retirement, or attempts to register after it and fails. A database marker is not a substitute for discovering external backup media.

## Operational limits

- Do not copy the database file while a process is writing. Use a coordinated consistent backup procedure.
- Preserve the database and its required key-wrapping material together, restrict access, and encrypt backup media.
- A failed or uncertain commit must be treated as unconfirmed; reopen and inspect state instead of assuming success or rollback.
- redb page checksums and ACID recovery are not cryptographic authenticity against an attacker who can rewrite the database file. The database file is not encrypted by this crate.
- These tests are deterministic transaction/reopen tests, not destructive power-loss certification across every storage controller or filesystem.

See [redb storage security notes](../../docs/security/redb-storage.md) and [ADR-0003](../../docs/adr/0003-storage-backend-contract.md).
