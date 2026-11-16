# ferrum-storage

The Community storage crate implements ADR-0003 using redb as the initial durable backend.

## Contract

`KvBackend` exposes versioned `get`, `put`, `delete`, prefix `list` with opaque cursors, compare-and-swap and atomic mutation batches guarded by expected-version or absence preconditions. Limits and malformed cursors are reported through typed errors.

`RedbStore` opens the database in `MultiWriter` mode and explicitly requests `Durability::Immediate` for every write transaction. The same database implements the Phase 1.6 `NonceUsageLedger`, `RotationStore` and `KeyDependencyInventory` contracts.

## Encryption boundary

The generic key/value methods persist opaque bytes. Callers must encrypt protected plaintext with `ferrum-crypto::barrier::BarrierCipher` before storing it. Use `put_encrypted` and `delete_encrypted` for FBE1 records so the live-key dependency index is updated atomically with the ciphertext record.

## Nonce and key lifecycle

The nonce ledger persists the high-water reservation and caller-supplied policy in one immediate-durability transaction before returning a reservation. Policy is immutable for each `(key_id, key_version)`. This crate does not select a nonce block size or AES-GCM rotation threshold; ADR-0004's owner-pending parameters remain explicit caller inputs.

The dependency inventory tracks live FBE1 records and explicit backup, snapshot and in-progress rotation-job registrations. Key retirement checks fail closed until the operator has reconciled the complete external inventory and marks it complete. A database marker is not a substitute for discovering external backup media.

## Operational limits

- Do not copy the database file while a process is writing. Use a coordinated consistent backup procedure.
- Preserve the database and its required key-wrapping material together, restrict access, and encrypt backup media.
- A failed or uncertain commit must be treated as unconfirmed; reopen and inspect state instead of assuming success or rollback.
- redb page checksums and ACID recovery are not cryptographic authenticity against an attacker who can rewrite the database file. The database file is not encrypted by this crate.
- These tests are deterministic transaction/reopen tests, not destructive power-loss certification across every storage controller or filesystem.

See [redb storage security notes](../../docs/security/redb-storage.md) and [ADR-0003](../../docs/adr/0003-storage-backend-contract.md).
