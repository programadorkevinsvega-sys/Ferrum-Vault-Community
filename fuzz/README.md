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

The envelope type currently fixes the nonce at `[u8; 12]`; fuzzing therefore covers
arbitrary nonce contents and malformed ciphertext/tag lengths. A serialized envelope
parser does not exist yet and must receive its own target when introduced.

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

KAT, Wycheproof, boundary and deterministic tamper tests remain separate from
fuzzing. Miri is not used as an oracle for AWS-LC's native cryptographic routines:
the provider delegates those operations through the native FFI boundary. For later
pure-Rust code, assess Miri separately and document applicability per component.
