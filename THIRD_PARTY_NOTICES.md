# Third-party notices and provenance

This file tracks third-party material distributed with or referenced by Ferrum Vault Community. It is not a substitute for each component's own license or notices.

## Initial Community foundation snapshot

At the time MPL-2.0 was provisionally added:

- No Rust crates, Cargo manifests, vendored source packages, native libraries or binary artifacts are included in this repository.
- `scripts/check_markdown_links.py` uses the Python standard library and is maintained as project code.
- GitHub Actions workflows reference external actions (including `actions/checkout`) by immutable commit SHA. Those actions execute in CI and are not copied into this repository; their upstream license and notice obligations remain with their respective projects.
- The Gitleaks workflow downloads and runs the upstream Gitleaks container by immutable image digest. It is a CI tool reference, not a vendored runtime dependency or part of the Community product.
- No third-party image, font, dataset or source-code snippet is currently declared as bundled product content.

## Maintainer requirements

Before adding a dependency, copied code, asset, generated artifact or runtime component:

1. Record its exact name, version or commit/digest, source URL and license identifier.
2. Preserve upstream copyright, patent, attribution and license notices.
3. Check compatibility with MPL-2.0 and the intended Community/Enterprise distribution boundary.
4. Do not assume that licensing the surrounding repository relicenses the third-party material.
5. Update this file and the applicable SBOM or dependency inventory when those artifacts are introduced.

If provenance or licensing is unclear, do not merge or publish the material until it has been reviewed.
