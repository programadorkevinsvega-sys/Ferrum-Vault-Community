# ADR-0028: Phase 2 durable audit, outbox and idempotency

- **Status:** Delegated technical selection recorded on 2026-11-16; requires Phase 2.0 owner acceptance before runtime implementation.
- **Scope:** Ferrum Vault Community Phase 2.
- **Supersedes:** No existing ADR. Preserves ADR-0003 storage boundaries and ADR-0005 durable, fail-closed audit requirements.
- **Specification:** [Phase 2 service contract](../phase-2/service-contract.md).

## Context

ADR-0005 requires a JSON hash-chain file plus stdout/syslog, configurable 90-day default retention, durable intent/outcome and fail-closed behavior. It also requires outbox, idempotency and reconciliation when audit and state do not share a transaction. The detailed event, append, retry and recovery semantics need a deterministic contract.

## Decision

1. Audit events use an explicit allowlisted schema and never contain request/response bodies, passwords, bearer tokens, Secret IDs, bootstrap tokens, Shamir shares, root material, private keys or protected plaintext.
2. Canonicalize event JSON using RFC 8785 JCS. Each JSONL line is `{ "event": <event>, "hash": <lowercase-hex-sha256> }`. Compute `hash = SHA-256(ASCII("FerrumVaultCommunityAuditV1") || 0x00 || previous_hash_32_bytes || sequence_u64_be || JCS(event))`; the event's `previousHash` is the 64-character lowercase-hex encoding of the prior 32-byte hash. The first record uses 32 zero bytes as the genesis hash. `sequence` is a strictly increasing base-10 uint64 string; its numeric value is encoded as unsigned 64-bit big-endian in the hash input. Any algorithm/schema change requires versioned verifier migration.
3. The JSONL hash-chain file is the authoritative local durable sink. Each required intent/outcome append is completely written and synchronized to stable storage before its dependent side effect or protected response. stdout is enabled by default as an additional sink; remote syslog is optional and must use authenticated TLS, not UDP.
4. The default retention is 90 days. Segment rotation carries the previous terminal hash; retention deletion preserves a verifiable chain checkpoint.
5. Sensitive mutations store state change, operation ID, idempotency record and audit outbox intent atomically when supported. Otherwise, persist and synchronize the intent/outbox before executing an idempotent handler; persist the outcome before acknowledging success.
6. Protected reads persist and synchronize audit intent before decrypting/disclosing data, and persist outcome before response release. If required audit persistence fails, the operation is blocked.
7. Idempotency keys are 128-bit random values scoped to principal + operation + key, retained 24 hours. Only key/request digests and non-secret operation references are stored. Reuse with a different request is a conflict. Secret-bearing results and ceremony shares are never cached or replayed; a retry cannot mint a second credential or disclose the original secret.
8. Pending outbox delivery uses bounded exponential retry and is never silently discarded. Defaults are 10,000 pending events and 60 seconds oldest age; crossing either threshold makes readiness false and rejects new sensitive operations.
9. Startup reconciliation handles every pending/ambiguous operation. If outcome cannot be proven, mark it indeterminate, block duplicate execution and require explicit repair. Never guess success/failure.
10. The host-local hash chain is tamper-evident only within its threat boundary and is not claimed to be immutable off-host retention.

## Consequences

- Required audit storage failure causes service degradation by design; availability does not override confidentiality or integrity.
- Every sensitive operation needs a stable operation ID and explicit idempotent/reconciliation semantics.
- Audit schemas and chain verification must be versioned and fuzz-tested.
- stdout/syslog mirrors are not substitutes for a durable authoritative append.

## Verification

Inject failures at every append/fsync/outbox boundary; test concurrent writers, crash/restart, truncation, reordering, hash tampering, duplicate idempotency keys, outcome ambiguity, full queues and audit-unavailable protected reads. Prove that no protected response or sensitive side effect precedes a durable intent.
