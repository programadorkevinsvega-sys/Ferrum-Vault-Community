# Ferrum cryptographic fuzzing

Fuzzing is part of the Phase 1.1 acceptance baseline and remains mandatory for
later phases whenever a component consumes attacker-controlled bytes, parses an
external format, or enforces a security boundary. Add a target in the same change
that introduces the relevant parser, envelope or protocol; do not defer fuzzing.

## Targets

| Target | Property under test |
|---|---|
| `seal_open_roundtrip` | Arbitrary AAD/plaintext never panic; provider-generated envelopes round-trip exactly and contain a 12-byte nonce plus 16-byte tag. |
| `open_arbitrary_payload` | Arbitrary AAD, nonce bytes and ciphertext/tag lengths passed to `open` never panic or release unauthenticated plaintext. |
| `authentication_mutations` | Changes to AAD, nonce, ciphertext or tag always fail authentication and return no plaintext. |
| `wrapped_key_decode` | Arbitrary bytes never panic the FVK1 parser; accepted envelopes re-encode byte-for-byte canonically. |
| `key_context_mutations` | Mutating the caller scope after AES-GCM wrapping always fails authentication. |
| `recovery_share_decode` | Arbitrary FRS1 input never panics; accepted envelopes remain byte-for-byte canonical. |
| `recovery_share_mutations` | Mutated Shamir shares either fail closed or reconstruct only the original test input. |
| `seal_bootstrap_transitions` | Arbitrary bootstrap token encodings and malformed/replayed bootstrap attempts never panic or move an uninitialized controller into an initialized state. |
| `root_quorum_authorization` | Root generate/rotate/revoke callbacks require an explicit 2-of-3 FRS1 policy and reject one, duplicate, corrupt, mixed-ceremony or arbitrary fragments. All secret values are generated at runtime. |
| `shamir_unsealer` | The mandatory default Shamir unsealer accepts only 2-of-3 shares from the expected ceremony and rejects one, duplicate, corrupt, mixed-ceremony, generic 5-of-3 and arbitrary fragments. |
| `barrier_envelope_decode` | Arbitrary FBE1 input never panics; accepted envelopes round-trip byte-for-byte and non-canonical/trailing data is rejected. |
| `barrier_aad_invariants` | Arbitrary canonical-path bytes produce deterministic AAD; path and key-version changes alter the authenticated encoding. |
| `barrier_nonce_rotation` | Explicit test policies plus an atomic ledger model never reuse reservation counters and require rotation before the configured use ceiling. |

The Phase 1.6 FBE1 envelope parser and ADR-0004 AAD encoder have dedicated fuzz
coverage. Nonce-budget fuzzing uses a synthetic atomic ledger only; it does not
stand in for a durable production adapter. The AES-GCM primitive's SealedPayload
keeps the nonce at [u8; 12] and ciphertext/tag bytes separately. The KMP layer adds the serialized FVK1
`WrappedKey` envelope; `wrapped_key_decode` fuzzes its strict decoder with
arbitrary bytes, while `key_context_mutations` checks authenticated FVC1 context
changes. Keep these targets separate because they exercise different boundaries.

## Run locally

The cargo-fuzz/libFuzzer toolchain requires Rust nightly and a supported Linux host
(x86_64 or aarch64). The nightly date and cargo-fuzz version below match CI.

```sh
rustup toolchain install nightly-2026-11-12 --profile minimal
cargo +nightly-2026-11-12 install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-11-12 metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1
cargo +nightly-2026-11-12 fuzz run seal_open_roundtrip -- -max_total_time=300 -max_len=65536 -timeout=10
cargo +nightly-2026-11-12 fuzz run open_arbitrary_payload -- -max_total_time=300 -max_len=65536 -timeout=10
cargo +nightly-2026-11-12 fuzz run authentication_mutations -- -max_total_time=300 -max_len=65536 -timeout=10
cargo +nightly-2026-11-12 fuzz run wrapped_key_decode -- -max_total_time=300 -max_len=65536 -timeout=10
cargo +nightly-2026-11-12 fuzz run key_context_mutations -- -max_total_time=300 -max_len=65536 -timeout=10
cargo +nightly-2026-11-12 fuzz run recovery_share_decode -- -max_total_time=300 -max_len=65536 -timeout=10
cargo +nightly-2026-11-12 fuzz run recovery_share_mutations -- -max_total_time=300 -max_len=65536 -timeout=10
cargo +nightly-2026-11-12 fuzz run seal_bootstrap_transitions -- -max_total_time=300 -max_len=65536 -timeout=10
cargo +nightly-2026-11-12 fuzz run root_quorum_authorization -- -max_total_time=300 -max_len=65536 -timeout=10
cargo +nightly-2026-11-12 fuzz run shamir_unsealer -- -max_total_time=300 -max_len=65536 -timeout=10
cargo +nightly-2026-11-12 fuzz run barrier_envelope_decode -- -max_total_time=300 -max_len=65536 -timeout=10
cargo +nightly-2026-11-12 fuzz run barrier_aad_invariants -- -max_total_time=300 -max_len=65536 -timeout=10
cargo +nightly-2026-11-12 fuzz run barrier_nonce_rotation -- -max_total_time=300 -max_len=65536 -timeout=10
```

## CI policy

- Pull requests and pushes to `main`: 60-second fuzz smoke test per target.
- Weekly scheduled workflow and manual dispatch: five minutes per target.
- Fuzzing runs on Linux, where the libFuzzer sanitizer runtime is supported. The seal and root-quorum targets create synthetic recovery shares at runtime; never commit real ceremony shares or bootstrap credentials.
- Failing inputs are retained as workflow artifacts. Minimize a finding, add a
  deterministic regression test, fix the defect, and keep the minimized regression
  fixture in version control when safe and useful.
- Commit curated, named seed inputs; do not commit every generated corpus mutation.
- The fuzz time budget is an execution budget, not proof of exhaustive coverage or
  absence of vulnerabilities.
- Recovery fuzzing uses synthetic runtime-generated values. The committed
  `recovery_share_decode` seed is a malformed FRS1 prefix, not a valid share or
  root-secret fixture. Never commit ceremony material or valid recovery shares.

## Other test techniques

Deterministic model/property sweeps complement coverage-guided fuzzing. KAT,
Wycheproof, boundary and deterministic tamper tests remain separate from fuzzing.
The KMP boundary has no internal shared mutable state, so Loom is not applicable.
CI runs pure-Rust KMP parser tests under Miri. Miri is not an oracle for AWS-LC
native cryptographic routines because the provider delegates those operations
through native FFI. Reassess both techniques for later pure-Rust stateful components.


### Durable storage cursor and record decoders

`storage_cursor_decode` feeds arbitrary bytes to the versioned prefix-cursor and versioned-record decoders exposed by `ferrum-storage`. The target runs in PR smoke and scheduled campaigns. Database I/O is intentionally excluded from this byte-decoder target; transaction behavior is exercised by deterministic concurrency, property and recovery tests.
