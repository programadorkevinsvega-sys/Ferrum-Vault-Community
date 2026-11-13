# ADR-0005: Request pipeline and fail-closed audit

- **Status:** Owner-approved.
- **Source decision:** Original Ferrum architecture ADR-0005, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community service pipeline, planned for Phase 2.

## Decision

The request pipeline is ordered as follows:

1. TLS 1.3 listener using rustls;
2. HTTP/gRPC server and request ID;
3. request size and time limits;
4. IP-based pre-authentication rate limit;
5. local seal-state check;
6. authentication;
7. identity-based rate limit;
8. canonical route and ACL evaluation;
9. handler; and
10. durable audit before and after sensitive operations.

Minimum audit destinations are a JSON file with hash-chain integrity and stdout/syslog. Retention is configurable, with a 90-day default.

## Fail-closed behavior

If a required audit-intent event cannot be persisted, the sensitive operation does not execute. For reads, the secret is not disclosed before the required event is durable. If all configured sinks fail, the operation is blocked. Record the result durably; use an outbox, idempotency and reconciliation when audit and storage do not share a transaction.

Only a minimal, explicit allowlist of non-sensitive endpoints may remain accessible while sealed.

## Consequences

There is no generic audit bypass or silent degradation. A local file hash chain detects modification but is not equivalent to immutable off-host retention against an attacker controlling the host. Export and archival details are deferred to their implementation phase.
