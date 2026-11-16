# redb storage security notes

## Scope and trust boundary

The initial Community persistence backend is redb 4.6.0, selected by ADR-0003. redb is an embedded storage engine, not a cryptographic provider. `ferrum-storage` stores opaque values; protected plaintext must be encrypted by the barrier before persistence. FBE1 records are kept in a dedicated table with a durable dependency index used during key retirement.

The database may contain ciphertext, FBE1 envelope metadata, nonce reservation metadata, rotation checkpoints, audit metadata and key-dependency indexes. It must not contain plaintext DEKs, seal-root material, Shamir shares, bootstrap tokens or unencrypted protected values.

## Durability and concurrency

`RedbStore` opens redb in `ConcurrencyMode::MultiWriter` and explicitly selects `Durability::Immediate` for writes. Writer transactions serialize through redb's multi-writer protocol. The nonce ledger commits its high-water mark before issuing a range. After restart the next reservation begins at that persisted mark; uncertain or partially consumed ranges are never reclaimed.

The following updates each share one transaction:
- nonce high-water reservation and immutable policy;
- FBE1 record changes and live-key dependency index;
- rotation record CAS and matching success/conflict audit event;
- rotation checkpoint and matching audit event;
- generic mutation batches and their preconditions.

## Key dependency completeness

The index tracks live FBE1 records. Backup, snapshot and active rotation-job references are registered explicitly and removed only after the external artifact/job is removed or migrated. `KeyDependencyInventory::has_dependencies` returns an incomplete-inventory error until an operator/integration has reconciled live data and all retained external artifacts.

A database with existing barrier records but no completeness marker fails closed. Read or metadata errors also fail closed. Never retire a DEK from an incomplete or unavailable inventory.

## Backup and recovery

Tests cover committed-state reopen, monotonic nonce reservations after reopen, concurrent non-overlapping reservations, rollback of an uncommitted transaction, checkpoint persistence, atomic CAS/audit and cursor properties. They do not simulate destructive power loss on every filesystem/device combination.

Backups must use a coordinated consistent snapshot/backup procedure. Preserve the database and required key-wrapping material together, encrypt backup media, restrict access, and register retained backup/snapshot references. A raw file copy while a writer is active is unsupported. Restore procedures and device durability assumptions require deployment-specific validation.

## Residual risks

- redb checksums and crash recovery protect consistency, not authenticity against a privileged filesystem attacker who can rewrite data and recompute checksums.
- Filesystem, device, controller and cloud-volume durability guarantees remain deployment dependencies.
- The dependency index knows only external backup/snapshot/job references that the operator/integration registers.
- Generic `KvBackend` methods accept opaque bytes. Service code must enforce encrypt-before-storage; use FBE1 methods to preserve key dependency accounting.
- Community remains a single logical tenant (`root`), not tenant isolation.
- ADR-0004's production nonce block size and AES-GCM rotation threshold remain unselected.
- This is not FIPS validation, an independent security audit or production certification.
