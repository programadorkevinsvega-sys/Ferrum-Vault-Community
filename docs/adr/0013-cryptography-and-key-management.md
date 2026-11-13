# ADR-0013: Cryptography and key-management provider

- **Status:** Owner-approved; numeric rotation threshold remains pending.
- **Source decision:** Original Ferrum architecture ADR-0013, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community cryptographic implementation.

## Decision

`aws-lc-rs` is the primary cryptographic provider. RustCrypto may be used only for primitives unavailable from the primary provider. The approved AEAD is AES-256-GCM with random 96-bit nonces. Custom cryptographic algorithms and modes are not permitted.

The public key-management provider contract exposes:

- `wrap(key_id, plaintext, context) -> WrappedKey{key_id, key_version, algorithm, ciphertext}`
- `unwrap(wrapped, context)`

The context binds the operation to its intended purpose and scope. The envelope and context encoding must be stable and authenticated.

Automatic rotation is configurable and must remain far below (2^{32}) encryptions per key. The exact threshold and quantitative safety margin remain pending and must not be guessed.

## Verification

Require KAT and applicable Wycheproof vectors, plus negative tests for invalid tags, incorrect AAD, nonce handling, rollover, resumable re-encryption and old-key retention. Selecting a library does not establish FIPS validation; no FIPS claim is authorized by this ADR.
