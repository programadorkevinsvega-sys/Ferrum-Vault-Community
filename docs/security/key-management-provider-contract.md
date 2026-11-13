# Key-management provider contract (Phase 1.2)

## Scope

This document specifies the Community implementation boundary for the owner-approved wrap/unwrap interface in ADR-0013. It defines the provider trait and stable public wire/context encodings. It does not implement AWS KMS, another remote provider, key hierarchy orchestration, seal/unseal, rotation, durable key storage or the storage barrier.

## Interface

KeyManagementProvider is an asynchronous, object-safe trait with Send + Sync bounds:

- wrap(key_id, plaintext, context) -> WrappedKey
- unwrap(wrapped, context) -> Zeroizing<Vec<u8>>

The wrapping key id, key version, algorithm identifier and ciphertext are retained in the envelope. Unknown key ids/versions or algorithms must fail closed. Successful unwrap returns only authenticated plaintext. Error variants are typed and their display strings never contain key material, context, plaintext or ciphertext.

## Key identifiers and algorithms

Key ids and algorithm ids are opaque ASCII tokens. They must start with an ASCII alphanumeric character and contain only ASCII alphanumeric characters or ., _, :, /, +, -. Each is encoded with an unsigned 16-bit big-endian byte length. A provider interprets key ids and must explicitly recognize algorithm identifiers it supports; FVK1 is not an algorithm negotiation protocol.

## Canonical authenticated context

Community is single-tenant and encodes tenant id root. A KeyContext contains that tenant id, one purpose token (seal-root, keyring-key or data-encryption-key), and caller-supplied canonical scope.

Its binary form is:

1. Four-byte magic FVC1.
2. Format version 1 as unsigned 16-bit big-endian.
3. Tenant id, purpose and scope, in that order, each prefixed by an unsigned 32-bit big-endian byte length.

The context is passed separately to wrap and unwrap; implementations must authenticate the exact context bytes with the wrapped-key operation. The exact FVC1 bytes are pinned by a golden compatibility vector in the crate tests. Callers must supply already-canonical scope bytes. Context normalization is deliberately not performed inside the provider boundary. This format is separate from the storage-barrier AAD layout specified by ADR-0004.

## FVK1 wrapped-key envelope

The decoder accepts exactly one complete envelope:

| Field | Encoding |
|---|---|
| Magic | ASCII FVK1 (4 bytes) |
| Format version | unsigned 16-bit big-endian; currently 1 |
| Key id length and bytes | unsigned 16-bit big-endian length, then validated ASCII id |
| Key version | nonzero unsigned 64-bit big-endian integer |
| Algorithm length and bytes | unsigned 16-bit big-endian length, then validated ASCII id |
| Ciphertext length and bytes | nonzero unsigned 32-bit big-endian length, then opaque bytes |

There are no optional fields, extensions or trailing bytes in version 1. A golden FVK1 byte vector is decoded and re-encoded by the conformance tests to pin field order, lengths and big-endian representation independently of the round-trip property checks. Unknown versions are rejected with a typed error. Length arithmetic is checked, reads are bounded against the input slice, and ciphertext is allocated only after its complete declared slice has been verified to exist. Any future incompatible change requires a new envelope version; do not reinterpret FVK1 fields in place.

The envelope metadata is security-sensitive. Providers must cryptographically bind key id, key version, algorithm identifier and context to the protected ciphertext (for example, through authenticated associated data or an equivalent provider-authenticated mechanism). They must not trust envelope claims without validating them against provider state. A caller must never be able to redirect an envelope to a different key/version or algorithm without authentication failure.

## Errors and asynchronous behavior

The contract distinguishes invalid caller input, malformed envelopes, unsupported format versions/algorithms, missing keys/versions, authentication failure, provider unavailability and generic provider failure. Public messages are intentionally generic.

Dropping an async future cancels the caller's wait; it does not guarantee that a remote provider has rolled back an operation already accepted. Implementations must never return partial plaintext or partial envelopes. Callers must treat a cancelled remote operation's outcome as unknown and follow the concrete provider's retry semantics. Do not assume retries are idempotent unless the provider documents it.

## Verification

The conformance suite uses a test-only AES-GCM reference provider to validate context and metadata authentication plus typed failure behavior. Golden byte vectors pin the FVC1 and FVK1 encodings; separate tests validate purpose binding and mutations of key id, version and algorithm metadata. It does not constitute a production local KEK store or cloud adapter. Deterministic property sweeps test canonical encode/decode round trips. Fuzz targets feed arbitrary bytes to the FVK1 decoder and mutate scope bytes after wrapping. CI runs bounded per-target smoke campaigns; scheduled/manual runs extend each campaign.

Loom is not applicable because this interface has no internal shared mutable state. CI runs the pure-Rust KMP parser tests under Miri; Miri is not used to validate AWS-LC native FFI internals. Provider performance benchmarks are deferred until an actual provider exists, because a test adapter would not yield representative provider measurements.
