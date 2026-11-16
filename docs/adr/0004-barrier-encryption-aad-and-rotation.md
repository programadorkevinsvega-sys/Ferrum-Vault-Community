# ADR-0004: Barrier encryption, AAD and key rotation

- **Status:** Owner-approved; numeric rotation and reservation parameters remain pending.
- **Source decision:** Original Ferrum architecture ADR-0004, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Public Community data-protection format and behavior.

## Decision

The key hierarchy is:

`seal root key → keyring key → versioned data-encryption keys (DEKs)`.

Protected data uses AES-256-GCM through `aws-lc-rs`, with a random 96-bit nonce. The envelope carries format version, key identifier and version, nonce, ciphertext and authentication tag.

AAD binds these fields in this exact order: `tenant_id`, `format_version`, `key_version`, `canonical_path`. Each field is encoded as a 32-bit big-endian byte length followed by its canonical bytes. Version values use canonical big-endian binary encoding. Variable-length values must never be joined using ambiguous separators or raw concatenation. Field order and encoding belong to the format version and cannot change in place.

Community reserves `tenant_id = "root"`. The tenant value is authenticated as AAD; it is not inferred from a client-controlled path prefix.

New writes use the active key version; reads select the recorded version. Background re-encryption is resumable, auditable and interruption-safe. Old key versions remain available until dependent records, backups and snapshots have been migrated.

## Nonce-budget and rotation safety

Nonce reservations are never reused. A reservation that may have been partially consumed is considered spent after failure or loss of proof of exact consumption. The single-node counter/high-water mark must be persisted before use. If a future cluster implementation reserves per-node blocks, a partially used block is also discarded after failure or leadership change.

The configurable rotation threshold must be far below (2^{32}) encryptions per key and account for aggregate use and random-nonce collision risk.

## Explicitly pending parameters

- Exact numeric AES-GCM rotation threshold and quantitative safety margin.
- Exact nonce-reservation block size.

These values must not be guessed. Failure to persist or obtain a safe nonce reservation must fail closed.

## Verification

KATs and applicable Wycheproof vectors are required, together with negative tests for modified ciphertext, tag, AAD, path and format/version mismatches. This design does not establish FIPS validation.


## Phase 1.6 implementation notes

The initial Community barrier format is FBE1 (format version 1). Its serialized envelope uses fixed fields: magic, u16-BE format version, u16-BE key-id byte length and ASCII key id, u64-BE key version, 12-byte nonce, u32-BE ciphertext-plus-tag length, and ciphertext with the complete 16-byte GCM tag. The decoder rejects unknown versions, zero key versions, invalid key identifiers, truncated lengths, undersized tags and trailing bytes.

For AAD format version 1, the version fields have explicit binary widths: format_version is u16-BE and key_version is u64-BE. Each is still encoded as a u32-BE length followed by those canonical bytes, and the four ADR-0004 fields remain in their approved order. canonical_path is supplied as already-canonical bytes by the storage/API boundary; this encoder does not normalize or infer paths.

NonceBudgetConfig deliberately has no default. It requires caller-supplied reservation block size and rotation threshold. The implementation rejects thresholds at or above 2^32 and discards any reservation block that would cross the configured threshold. This hard cryptographic ceiling is not a substitute for the still-pending owner-selected threshold and quantitative safety margin. The NonceUsageLedger contract requires atomic, durable high-water reservation before use; Phase 1.7 supplies its concrete redb adapter.

The rotation worker requires stable key-ordered pagination, a durable checkpoint, atomic CAS plus audit for each rewritten record, and atomic checkpoint plus audit. Key retirement requires a complete inventory of live records, backups, snapshots and in-progress jobs. These contracts are backend-neutral; production durability is not claimed until Phase 1.7 implements and tests them.

A page containing any compare-and-swap conflict is checkpointed at its original starting cursor and remains incomplete. The worker replays that page on its next invocation; already migrated rows are authenticated and skipped, while conflicted records are read again. A job must not report completion while a conflict remains unresolved.
