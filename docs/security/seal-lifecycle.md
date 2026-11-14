# Seal lifecycle and bootstrap — Phase 1.4

## Scope and status

This document records the Community Phase 1.4 implementation boundary. The crate implements a process-local lifecycle state machine and bootstrap/unseal handling. It is not a deployed service, durable state store, HTTP API or production authorization integration.

The approved root ceremony remains offline and Shamir-based. The service never persists recovery shares. Bootstrap and later unseal operations accept a threshold set of FRS1 shares, reconstruct the secret in zeroizing memory, and verify the FRS1 integrity tag before committing a state transition.

## State model

| Current state | Operation | Next state | Preconditions |
|---|---|---|---|
| Uninitialized | issue bootstrap token | Uninitialized | No active token; no token consumed |
| Uninitialized | bootstrap | Sealed | Valid, unexpired token and valid threshold from one FRS1 ceremony |
| Sealed | unseal | Unsealed | Shares reconstruct the same configured ceremony |
| Unsealed | seal | Sealed | Active root buffer exists |

All other transitions fail closed. The controller serializes updates and checks a generation counter after recovery work so simultaneous bootstrap or unseal attempts cannot both commit.

## Bootstrap token

A token contains 32 random bytes from AWS-LC's operating-system-backed random source. Its verifier is SHA-256 over a domain separator, the token length and token bytes. Only the verifier is retained in the controller; diagnostic formatting redacts token material.

The caller must explicitly supply a positive lifetime. There is no default TTL. Expiry is checked with Rust's monotonic `Instant`, not wall-clock time. An expired, unused token may be replaced while the controller remains Uninitialized. A valid token is consumed in the same critical section that binds the ceremony and changes state to Sealed. Replays, missing credentials, wrong credentials and expired credentials return the same public rejection error.

The token object is non-Clone and has no serialization or Display implementation. The explicit byte accessor exists only for secure handoff to the bootstrap operator. It must never be placed in logs, fixtures, ordinary telemetry, shell history, chat or CI artifacts.

## Binding the root ceremony

FRS1 already contains a random 128-bit ceremony identifier in its authenticated header. The recovery type now exposes only this non-secret identifier as metadata. Bootstrap checks that all supplied shares use the same identifier, reconstructs the root through ferrum-recovery, and relies on its HMAC verification before recording the identifier.

The controller does not retain the reconstructed root during bootstrap. It records only the ceremony identifier. During unseal it requires the same identifier, reconstructs the root again, verifies the FRS1 integrity tag, and stores the recovered root in a Zeroizing buffer.

This avoids inventing a second root fingerprint or a new cryptographic format. It does not provide custodian identity or per-share signatures; those limitations remain as documented by the Phase 1.3 recovery runbook.

## Seal and unseal memory behavior

The root is never returned from the controller as an owned buffer. A caller may use it only through a scoped callback while the controller is Unsealed. The callback must not retain or copy the bytes. Calling seal changes the state to Sealed and drops the zeroizing buffer.

Zeroization is best-effort. It cannot promise removal of every copy in registers, swap, firmware, crash dumps or caller-owned copies. The crate contains no unsafe code and does not claim OS memory locking.

## Persistence and production blockers

The current controller uses process-local memory. It is not restart-safe or multi-process. This is intentionally not disguised as durable behavior: Phase 1.7 must provide atomic persistence for lifecycle state, ceremony identifier and consumed-bootstrap status before this controller is wired into a real service. Monotonic token expiry is process-local; a future durable adapter must invalidate outstanding bootstrap credentials on process restart or provide a separately approved safe clock model.

No API-level rate limiting or durable audit sink exists yet. A service integration must add abuse throttling, fail-closed audit and generic external errors without logging tokens, shares or root material.

## Root-operation quorum and derived-credential revocation

The owner has approved an explicit **2-of-3** quorum for `generate-root`, root rotation and root revocation. Derived-credential revocation does not require root quorum, but must be audited.

Configure the root controller explicitly with `RootQuorumPolicy::new(2, 3)`. `SealController::new()` installs no quorum policy. Missing configuration, M < 2, M > N, or a root FRS1 set whose encoded policy does not match the explicit configuration causes a fail-closed rejection. The general `ferrum-recovery` 5-of-3 default remains separate; it is not an implicit root-operation quorum.

`with_root_quorum` is the shared gate for the three root operations. It verifies at least M and at most N shares, exact FRS1 policy, the currently bound ceremony identifier, unique participant IDs and the FRS1 integrity tag. One fragment is insufficient; two distinct valid fragments work. Duplicate, corrupted and cross-ceremony fragments are rejected. It drops the reconstructed secret before invoking the operation callback and gives the callback only non-secret operation context. The callback runs under the controller's state lock and must not re-enter the controller. This is an in-process authorization boundary, not yet a durable root-mutation service or HTTP endpoint.

The `revoke_derived_credential` helper does not accept or request root fragments. It requires a caller-provided `AuditSink`, records a request before invoking the revocation callback, and records success/failure using a domain-separated fingerprint of the credential reference (never the raw reference). If the audit sink cannot accept the request event, the revocation callback does not run. A durable audit implementation belongs to the service/audit phase.

Root fragments, root material and bootstrap credentials must never enter source control, logs, CI output, CI variables or CI artifacts. Tests and fuzzing generate synthetic material at runtime only. See ADR-0014.

## Verification

Tests cover invalid transitions, positive/zero lifetime, expiry and reissue, token redaction, wrong-token non-consumption, successful one-time bootstrap, replay, insufficient/failed recovery, ceremony mismatch, alternate valid threshold subsets, seal/unseal root visibility, concurrent bootstrap and unseal races, panic recovery of the mutex, and deterministic root-length property sweeps.

The `seal_bootstrap_transitions` libFuzzer target uses only runtime-generated synthetic secrets/shares. It mutates FRS1 share bytes and feeds arbitrary token byte strings to the controller. No valid ceremony shares, root keys or bootstrap credentials are committed as corpus data.
