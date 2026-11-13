# Third-party notices and provenance

This file tracks third-party material distributed with or referenced by Ferrum Vault Community. It is not a substitute for each component's own license or notices.

## Cryptographic runtime dependency

- **aws-lc-rs 1.19.0** — exact version pin; source: https://github.com/aws/aws-lc-rs/tree/v1.19.0; upstream package SPDX expression: ISC AND (Apache-2.0 OR ISC).
- AWS-LC is brought in through the upstream aws-lc-sys dependency. Cargo.lock records resolved native wrapper and transitive package versions and checksums.
- The Community crate selects the explicit non-fips feature. This is not a FIPS validation claim.
- The upstream non-FIPS build requires a C/C++ compiler. Upstream documentation says CMake, bindgen and Go are not required for this build path.

## Cryptographic test vectors

- **C2SP Wycheproof AES-GCM vectors** — testvectors_v1/aes_gcm_test.json, source commit 65ca494727a52944c204441c860b039e6786b99b, blob 223f53cad33d78013ed635d94889836c036e1d58.
- The fixture is reproduced at crates/crypto/tests/vectors/aes_gcm_test.json. The applicable AES-256-GCM profile is filtered by key size 256 bits, IV size 96 bits and tag size 128 bits.
- Wycheproof test data is distributed under Apache License 2.0. The exact upstream license text is retained at crates/crypto/tests/vectors/LICENSE-APACHE-2.0.txt.

## Benchmark dependency

- **Criterion 0.8.2** — development-only benchmarking dependency, source: https://github.com/criterion-rs/criterion.rs; dual-licensed under Apache-2.0 and MIT. It is not included as a runtime dependency.

## Initial Community foundation snapshot

- The project Markdown validator uses the Python standard library and is maintained as project code.
- GitHub Actions workflows reference external actions by immutable commit SHA. Those actions execute in CI and are not copied into this repository; their upstream license and notice obligations remain with their respective projects.
- The Gitleaks workflow downloads and runs the upstream Gitleaks container by immutable image digest. It is a CI tool reference, not a vendored runtime dependency or part of the Community product.

## Maintainer requirements

Before adding a dependency, copied code, asset, generated artifact or runtime component:

1. Record its exact name, version or commit/digest, source URL and license identifier.
2. Preserve upstream copyright, patent, attribution and license notices.
3. Check compatibility with MPL-2.0 and the intended Community/Enterprise distribution boundary.
4. Do not assume that licensing the surrounding repository relicenses the third-party material.
5. Update this file and the applicable SBOM or dependency inventory when those artifacts are introduced.

If provenance or licensing is unclear, do not merge or publish the material until it has been reviewed.
