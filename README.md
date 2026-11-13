# Ferrum Vault Community

Ferrum Vault is a project in development for secrets management, encryption services and public-key infrastructure, planned in Rust.

## Project status

**Pre-implementation / architecture foundations.** The current Community repository contains public project documentation only. It does not yet contain a Rust implementation, Cargo manifests, a runnable server, a CLI, or a production-ready release.

Do not use this project to store, protect or process production secrets. It has not been independently audited or FIPS validated.

## Community and Enterprise

- **Community (this repository):** the public edition. It will contain only code, APIs, documentation and extension points approved for public release.
- **Enterprise:** a separate private edition for proprietary implementation and internal engineering materials.

Community must remain independently buildable and must never depend on Enterprise. Enterprise may consume documented, versioned Community interfaces. Enterprise code, internal ADRs, full threat models and internal roadmaps are not part of this repository.

## Documentation

- [Architecture overview](docs/architecture-overview.md)
- [Edition boundaries](docs/decisions/edition-separation.md)
- [Public roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [License status](LICENSE-STATUS.md)

## License

The Community edition is provisionally published under the **Mozilla Public License 2.0 (MPL-2.0)**. The exact, unmodified license text is in [LICENSE](LICENSE). See [LICENSE-STATUS.md](LICENSE-STATUS.md) for the provisional status and the legal-review checklist.

MPL-2.0 is a file-level weak-copyleft license: source files covered by it and modifications to those files must remain available under MPL-2.0 when distributed, while a larger work may contain separate files under other terms if the MPL conditions are met. This is a summary, not a substitute for the license text.

## Project name

“Ferrum Vault” is a working project name. Trademark and naming clearance must be completed before commercial/public product launch.
