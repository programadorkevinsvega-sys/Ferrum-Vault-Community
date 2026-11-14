# Contributing

Thank you for your interest in Ferrum Vault Community.

## Current contribution scope

The project is in early implementation of Phase 1. Cryptographic, recovery and seal-lifecycle code is being added incrementally under the public roadmap. Changes must stay within the approved phase, include tests and fuzz targets for new security boundaries, update affected documentation, and must not present an isolated crate as a production-ready service.

Before proposing a significant architectural or security change, open a discussion or issue describing the problem and the intended public impact. Do not introduce new cryptographic algorithms, unapproved dependencies, generated binaries, unresolved security parameters or production-readiness claims. Preserve owner-approved decisions and leave explicitly pending parameters unresolved.

## Licensing and provenance

- Community contributions are intended to be distributed under the repository's [MPL-2.0 license](LICENSE). Read the full license before contributing.
- By submitting a contribution, you represent that you created it or have sufficient rights to submit it under MPL-2.0, consistent with the contributor representation in Section 2.5 of that license.
- Do not submit employer-owned, client-owned, confidential, copied or third-party material unless you have verified permission and compatible licensing.
- Identify the source and license of any third-party code, assets, datasets, generated files or substantial copied snippets. Preserve required notices. Do not silently relicense third-party material under MPL-2.0.
- Do not submit material produced by another person or tool unless you have the rights and authority to license it.
- The project has not yet adopted a CLA or DCO. This statement is not a substitute for a future formal inbound-contribution policy; maintainers may defer external code contributions until that policy is approved.

## Pull requests

- Keep changes focused and explain the user-facing reason.
- Update affected public documentation and links.
- Include validation evidence for documentation or scripts.
- Do not copy internal Enterprise documents, roadmaps, threat models, code or design notes into Community.
- Do not include credentials, private keys, recovery material, customer data or other secrets.
- Preserve all existing copyright, patent, license and attribution notices.

The public Community edition must remain independently usable and must never require the private Enterprise repository.
