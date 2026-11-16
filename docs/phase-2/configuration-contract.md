# Phase 2 — Configuration contract

- **Status:** Delegated technical selection on 2026-11-16; applies to Community Phase 2.
- **Normative parent:** [Native service contract](service-contract.md).
- **Format:** strict TOML. Unknown/duplicate fields and invalid or unsafe values are fatal configuration errors.

## 1. Configuration sources and precedence

Values are resolved in this order, lowest to highest:

1. Compiled safe defaults.
2. Explicit TOML file (default path: `/etc/ferrum/ferrum.toml` on Linux; CLI may supply another path).
3. Explicitly documented `FERRUM__...` environment overrides for non-secret settings.
4. Explicit CLI flags for non-secret settings.

No secret value is accepted as a CLI argument or environment variable. Configuration may contain paths to secret files, but never passwords, bearer tokens, Secret IDs, root shares, private-key contents or cloud credentials. The service must redact config values from diagnostics.

Unknown keys, duplicate keys, type coercion, invalid enum values, malformed CIDRs, relative security-sensitive paths and out-of-range numbers cause startup failure. No security control may silently fall back to an insecure default.

## 2. Required sections

| Section | Required values | Default / policy |
|---|---|---|
| `server` | bind address, connection/request concurrency, timeouts | Bind `127.0.0.1:8443`; 512 connections; 256 in-flight requests |
| `server.tls` | server certificate and private-key paths | Required; TLS 1.3 only; rustls; no plaintext or insecure mode |
| `server.tls.client_auth` | client CA bundle, SAN mapping and CRL paths when mTLS is enabled | Separate from server trust; missing required revocation data fails mTLS closed |
| `server.trusted_proxy_cidrs` | exact trusted proxy networks | Empty by default; forwarded headers ignored |
| `limits` | request/message/header/path/nesting limits | 1 MiB body/message; 16 KiB headers; 8 KiB request target; JSON depth 32 |
| `timeouts` | header/body/handler/idle limits | 5s / 10s / 15s / 60s; handler hard maximum 30s |
| `rate_limit` | pre-auth, login, unseal and identity buckets | Mandatory; defaults in Section 4 |
| `auth` | token TTL ceilings, Argon2id parameters and work concurrency | Mandatory; defaults in Section 5 |
| `ceremony` | unseal/root session lifetimes and active-session limits | 5 minutes; unseal 1 active session |
| `storage` | redb data directory | Required, absolute, service-owned and non-symlink |
| `audit` | hash-chain file, stdout and optional TLS syslog | File + stdout enabled; 90-day retention |
| `outbox` | maximum pending and oldest pending age | 10,000 events / 60 seconds |
| `clock` | backwards-jump threshold | 30 seconds |

## 3. File and permissions

- Linux service config directory: `/etc/ferrum`, root-owned and not writable by the service account. Config mode normally `0640`, private key mode `0600`.
- Storage and audit directories are absolute paths, owned by the service account and mode `0700`; files default to `0600`.
- Reject symlink traversal in sensitive directory/file paths. Use safe file-open flags and verify ownership/mode at startup.
- Server certificate, private key, client CA bundle and CRL are distinct inputs. Server and client trust cannot be implicitly merged.
- Config validation runs before opening the listener. `ferrum-server --check-config` must parse, validate bounds, check required files and report only safe field names/errors; it must not print key contents or secret values.
- Configuration is not fetched from remote URLs in Phase 2. There is no implicit cloud secret manager or AWS SDK dependency.

## 4. Request and rate limits

Defaults are intentionally aligned with [service-contract.md](service-contract.md#9-request-and-resource-limits):

| Setting | Default |
|---|---:|
| `limits.max_http_body_bytes` | 1,048,576 |
| `limits.max_grpc_message_bytes` | 1,048,576 |
| `limits.max_header_bytes` | 16,384 |
| `limits.max_request_target_bytes` | 8,192 |
| `limits.max_json_depth` | 32 |
| `limits.max_json_string_bytes` | 262,144 |
| `limits.default_page_size` | 50 |
| `limits.max_page_size` | 100 |
| `timeouts.header_read_ms` | 5,000 |
| `timeouts.body_read_ms` | 10,000 |
| `timeouts.request_ms` | 15,000 |
| `timeouts.max_request_ms` | 30,000 |
| `timeouts.keep_alive_idle_ms` | 60,000 |
| `server.max_connections` | 512 |
| `server.max_in_flight_requests` | 256 |
| `rate_limit.preauth_per_ip_per_minute` | 60 |
| `rate_limit.preauth_burst` | 20 |
| `rate_limit.login_per_ip_per_minute` | 10 |
| `rate_limit.login_per_identifier_per_minute` | 5 |
| `rate_limit.unseal_attempts_per_ip_per_15m` | 5 |
| `rate_limit.authenticated_per_identity_per_minute` | 600 |
| `rate_limit.authenticated_burst` | 120 |
| `rate_limit.admin_mutations_per_identity_per_minute` | 60 |
| `rate_limit.admin_mutation_burst` | 10 |

Hard bounds may be equal to defaults for parser-facing maximums. An operator may lower limits. Raising a hard maximum requires a new reviewed contract/ADR because it changes denial-of-service exposure. If the persistent rate-limit backend is unavailable, authentication and protected operations fail closed; no emergency disable flag is supported.

## 5. Authentication and ceremony defaults

| Setting | Default / maximum |
|---|---|
| Access token TTL | 900 seconds default |
| Standard access token maximum TTL | 28,800 seconds |
| Privileged token TTL | 300 seconds |
| Privileged token maximum | 900 seconds; non-renewable |
| Argon2id memory | 65,536 KiB |
| Argon2id iterations | 3 |
| Argon2id parallelism | 4 |
| Argon2id concurrent operations | 4 |
| Argon2id queue | 8 |
| AppRole Secret ID TTL | 86,400 seconds default; 2,592,000 seconds maximum |
| AppRole Secret ID uses | 1 default; 10 maximum |
| AppRole role token TTL | 900 seconds default; 3,600 seconds maximum |
| Bootstrap token TTL | 300 seconds; one use |
| Unseal session TTL | 300 seconds; one active session |
| Root-operation approval TTL | 300 seconds |

A setting that could weaken credential policy is not configurable above its stated maximum. Local tests may inject much smaller values through test-only constructors; production config cannot.

## 6. TLS and proxy behavior

- `server.tls.cert_file` and `server.tls.key_file` are required. TLS 1.3 is fixed and cannot be lowered.
- mTLS is enabled only when its trust bundle, exact SAN-to-principal mappings and required revocation material are present and valid.
- `server.trusted_proxy_cidrs` is empty by default. The source peer address is authoritative. If networks are added, only RFC 7239 `Forwarded` values received directly from those peers are trusted; at most five hops are parsed. Malformed, obfuscated or ambiguous chains are rejected. `X-Forwarded-For` is never authoritative.
- A proxy must connect to Ferrum over a separately authenticated TLS link. A certificate identity forwarded in an HTTP/gRPC header is never trusted.
- TLS 0-RTT is always disabled.

## 7. Audit and clock

- The hash-chained JSONL audit file is the authoritative local durable sink. stdout is enabled by default as the additional minimum destination. Optional remote syslog must use TLS and peer verification; UDP syslog is not accepted for the security audit stream.
- Retention defaults to 90 days. The service must preserve a verifiable chain checkpoint when old segments are removed.
- An audit append/fsync failure blocks the dependent sensitive operation or protected response. The service does not continue with an in-memory-only audit fallback.
- Outbox readiness thresholds are 10,000 pending events or 60 seconds oldest age; either makes readiness false and blocks new sensitive operations.
- Durations use monotonic time; persisted absolute expiries and certificate validity use UTC wall clock. A backwards wall-clock jump greater than 30 seconds enters `clock_unsafe` and blocks new credential issuance/renewal and mTLS auth until repaired and explicitly acknowledged locally.

## 8. Reload and shutdown

- Only certificate/key and client CRL/trust bundle material may be hot-reloaded in Phase 2. A candidate bundle is fully validated before atomic swap; invalid input leaves the previous known-good configuration active.
- Rate limits, auth ceilings, audit sink topology, storage path, listener address and trust-proxy networks require restart.
- Graceful shutdown stops accepting new connections, drains in-flight requests for at most 30 seconds, propagates cancellation, and completes or durably marks every sensitive operation for reconciliation. It never discards an intent or unseal/root share silently.
- No API endpoint mutates server configuration in Phase 2. Operators change the local config and restart/reload by the documented path.

## 9. Change control

Any increase to a hard maximum, new configuration source, new trusted proxy behavior, weaker TLS, longer credential lifetime, new audit sink fallback or reduced durability guarantee requires a reviewed ADR and security tests. Configuration defaults do not replace operator threat modelling, network controls, backup plans or independent security review.
