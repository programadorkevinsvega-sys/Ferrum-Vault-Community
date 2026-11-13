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

The AES-GCM primitive's `SealedPayload` keeps the nonce at `[u8; 12]` and
ciphertext/tag bytes separately. The KMP layer adds the serialized FVK1
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
```

## CI policy

- Pull requests and pushes to `main`: 60-second fuzz smoke test per target.
- Weekly scheduled workflow and manual dispatch: five minutes per target.
- Fuzzing runs on Linux, where the libFuzzer sanitizer runtime is supported.
- Failing inputs are retained as workflow artifacts. Minimize a finding, add a
  deterministic regression test, fix the defect, and keep the minimized regression
  fixture in version control when safe and useful.
- Commit curated, named seed inputs; do not commit every generated corpus mutation.
- The fuzz time budget is an execution budget, not proof of exhaustive coverage or
  absence of vulnerabilities.

## Other test techniques

Deterministic model/property sweeps complement coverage-guided fuzzing. KAT,
Wycheproof, boundary and deterministic tamper tests remain separate from fuzzing.
The KMP boundary has no internal shared mutable state, so Loom is not applicable.
CI runs pure-Rust KMP parser tests under Miri. Miri is not an oracle for AWS-LC
native cryptographic routines because the provider delegates those operations
through native FFI. Reassess both techniques for later pure-Rust stateful components.
