# Barrier encryption, AAD, nonce accounting and rotation — Phase 1.6

## Scope and status

This document describes the Community Phase 1.6 storage barrier API and the contracts that a durable backend must implement. It is not a deployed storage service. The keyring currently manages in-process key handles; Phase 1.7 must persist key metadata, nonce reservations, rotation checkpoints and record updates in redb before this can be used as a durable production barrier.

The approved hierarchy remains seal root key → keyring key → versioned DEKs. Phase 1.6 accepts a versioned DEK handle supplied by the caller; key wrapping/unwrapping continues to use the asynchronous KeyManagementProvider contract. The module does not derive DEKs directly from the root or expose root material.

## AAD and canonical path

FBE1 format version 1 authenticates these exact ADR-0004 fields, in order:

1. tenant id: the fixed Community value root;
2. format version: u16 big-endian;
3. key version: u64 big-endian;
4. canonical path: the exact bytes supplied by the canonical path boundary.

Every field is encoded as a u32 big-endian byte length followed by the field bytes. No delimiter concatenation, normalization, case folding or path inference occurs in the barrier encoder. A caller must supply the exact canonical path that identifies the same storage object on write and read. AAD schema changes require a new format version; version 1 cannot be changed in place.

## FBE1 envelope

The strict serialized layout is magic FBE1, u16-BE format version, u16-BE key-id length, ASCII key id, u64-BE key version, 12-byte random nonce, u32-BE ciphertext-and-tag length, and ciphertext with the complete 16-byte GCM tag appended. Decoding rejects unknown format versions, zero key versions, invalid identifiers, ciphertext shorter than the tag, truncation, overflow and trailing bytes.

New writes select the keyring's active version. Reads select the exact version carried by the envelope and fail closed if that key is unavailable. Wrong key id, path, AAD, version or authentication tag never returns plaintext. Scratch plaintext buffers used by the rotation worker are wrapped in zeroizing guards.

## Nonce-use reservations

AWS-LC continues to generate a fresh random 96-bit nonce for each AES-256-GCM invocation. Before encryption, the barrier consumes one ticket from a per-key-id/per-key-version reservation. The NonceUsageLedger contract must atomically reserve a non-overlapping half-open counter range and durably commit the high-water mark before returning. A reservation is never rolled back; if use may have started or its consumption cannot be proven, the unused remainder is discarded after failure/restart.

There is intentionally no in-memory production implementation and no default policy. NonceBudgetConfig requires explicit non-zero reservation block size and rotation threshold. It rejects thresholds at or above 2^32 and refuses an entire block if that block would exceed the configured threshold. The exact operational threshold, safety margin and block size remain pending owner decisions; the less-than-2^32 validation is a hard ceiling, not an approved production setting.

## Key activation, re-encryption and retention

Installing a strictly newer DEK version switches the in-process active version for subsequent writes while retaining older versions for reads. The rotation worker processes a stable ordered page, decrypts each old-version envelope with its recorded key, encrypts with the active key, and calls the store's compare-and-swap operation. Already migrated records are skipped on replay. CAS success/conflict audit events must commit atomically with the corresponding CAS result; page checkpoint advancement and its audit event must also commit atomically. Any page with a CAS conflict remains incomplete and keeps its starting cursor so the worker replays it; already-migrated rows are authenticated and skipped, while conflicted rows are re-read. A changed active key version invalidates an in-progress job rather than mixing target versions.

Retiring an old key requires an injected KeyDependencyInventory that checks live records, backups, snapshots and in-progress rotation jobs. Any incomplete or unavailable inventory fails closed. A production implementation must serialize retirement against restore/retention changes.

## Phase 1.7 durable backend obligations

The Phase 1.6 contracts are intentionally backend-neutral. Phase 1.7 must implement them with the approved initial redb backend and prove:

- nonce reservation high-water updates are durable before ticket return and linearizable across concurrent callers;
- partially consumed blocks are never reused after crash/restart;
- stable pagination and cursor recovery do not omit records;
- record CAS and matching audit event are one atomic transaction;
- checkpoint and checkpoint-audit update are one atomic transaction;
- key dependency inventory covers live data, backups, snapshots and active jobs;
- tests inject failures around each persistence boundary and demonstrate restart/resume safety.

Until those checks pass, the Phase 1.6 API is not an authorization to encrypt production records or claim durable rotation.

## Validation

Unit and property tests cover the golden AAD vector, path/key-version binding, FBE1 canonical round trips, invalid/truncated/trailing envelopes, active/new and retained/old key selection, nonce block disjointness, ledger failure, key-retention gates and restartable page rotation. Dedicated libFuzzer targets cover FBE1 decoding, AAD invariants and nonce/rotation budget state. Miri is used only for the pure-Rust AAD encoder test; native AWS-LC AEAD operations are not treated as Miri-compatible.
