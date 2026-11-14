# Ferrum Vault Community

Ferrum is a project in development for secrets management, encryption services and public-key infrastructure, planned in Rust.

## Project status

**Early implementation / not production-ready.** The Community repository now contains isolated Rust crates for the AWS-LC cryptographic boundary, offline Shamir recovery and the Phase 1.4 seal/bootstrap state machine. It does not yet contain a complete runtime, durable seal-state backend, server/API or CLI. Do not use it to store, protect or process production secrets.

Do not use this project to store, protect or process production secrets. It has not been independently audited or FIPS validated.

## Community and Enterprise

- **Community (this repository):** the public edition. It will contain only code, APIs, documentation, tests and extension points approved for public release.
- **Enterprise:** a separate private edition for proprietary implementation and internal engineering materials.

Community must remain independently buildable and must never depend on Enterprise. Enterprise may consume documented, versioned Community interfaces. Proprietary implementation and private engineering records are not part of this repository.

## Documentation

- [Public architecture overview](docs/architecture-overview.md)
- [Community Architecture Decision Records](docs/adr/README.md)
- [Edition boundaries](docs/decisions/edition-separation.md)
- [Community roadmap](ROADMAP.md)
- [Migration and decision provenance](MIGRATION.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [License status](LICENSE-STATUS.md)

## License

The Community edition is provisionally published under the **Mozilla Public License 2.0 (MPL-2.0)**. The exact, unmodified license text is in [LICENSE](LICENSE). See [LICENSE-STATUS.md](LICENSE-STATUS.md) for the operative provisional status and the legal-review checklist.

“Provisional” describes pending project legal review; it does not modify the MPL-2.0 terms or make the published license a non-binding draft. MPL-2.0 is a file-level weak-copyleft license. This is a summary, not a substitute for the license text.

## Project name

“Ferrum” is a working project name. Trademark and naming clearance must be completed before commercial/public product launch.
