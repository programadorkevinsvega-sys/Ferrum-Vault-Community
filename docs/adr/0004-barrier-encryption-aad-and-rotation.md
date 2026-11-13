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
