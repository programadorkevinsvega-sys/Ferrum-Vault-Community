# ADR-0029: Phase 2 server TLS and strict configuration

- **Status:** Delegated technical selection recorded on 2026-11-16; requires Phase 2.0 owner acceptance before runtime implementation.
- **Scope:** Ferrum Vault Community Phase 2.
- **Supersedes:** No existing ADR. Preserves the TLS 1.3/rustls requirement in ADR-0005 and server-hardening boundary in ADR-0022.
- **Specification:** [Configuration contract](../phase-2/configuration-contract.md), [example TOML](../../examples/ferrum.phase2.example.toml), and [service contract](../phase-2/service-contract.md).

## Decision

- One listener carries HTTP/JSON and gRPC; default bind is loopback `127.0.0.1:8443`. An operator must explicitly configure remote exposure.
- TLS 1.3 only using rustls; ALPN is `h2` and `http/1.1`; 0-RTT and plaintext fallback are disabled. The current TLS 1.3 specification is RFC 9846.
- Server certificate/key, client CA trust, SAN mapping and CRL material are separate configuration inputs. mTLS fails closed if required trust or revocation material is absent, invalid or expired.
- Certificate/key/CRL reload is atomic: validate a complete candidate before swapping. An invalid reload keeps the previous known-good snapshot and emits a security/health event.
- Service configuration is strict TOML. Unknown/duplicate keys, unsafe paths, invalid types and out-of-range security settings fail startup. Root operations additionally require explicit `[ceremony.root_quorum]` values `threshold = 2` and `total_shares = 3`; missing/invalid values disable root operations and never select a fallback. At most one root operation may be active. The precedence is safe compiled defaults, file, documented non-secret environment overrides, then non-secret CLI flags.
- Secret values are never read from command-line arguments or environment overrides; configuration contains file references only. Sensitive directories/files have restrictive ownership/modes and reject symlink traversal.
- Only TLS certificate/key and client revocation/trust bundle material may hot-reload in Phase 2. Other security-sensitive settings require restart.
- Graceful shutdown stops accepting requests, drains for at most 30 seconds, propagates cancellation and durably reconciles sensitive in-flight operations.

## Consequences

The service has a secure local default and no accidental public listener. Operators must explicitly configure bind address, certificates and any trusted reverse proxies. Misconfiguration prevents startup or the affected authentication mode rather than silently weakening transport security.

## Verification

Test TLS 1.3-only negotiation, reject TLS 1.2/plaintext/0-RTT, validate EKU/SAN/chain/expiry/revocation, proxy-header spoofing, symlink/path permission checks, strict config parsing, failed reload rollback and bounded graceful shutdown.
