# ADR-0002: Async extension contracts

- **Status:** Owner-approved.
- **Source decision:** Original Ferrum architecture ADR-0002, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Public Community extension points.

## Decision

Pluggable public boundaries that require dynamic dispatch—such as authentication methods, providers and audit sinks—use `async_trait` with `Send + Sync`. Internal hot paths prefer native `async fn` and generics where dynamic dispatch is unnecessary.

Every trait documents cancellation behavior, lifetimes, errors, concurrency and security guarantees. Compile-time tests verify the required dynamic compatibility when implementations are introduced.

## Security considerations

Implementations must not retain references to secret material beyond their valid scope. Cancellation must preserve state and resource invariants. These are design requirements; no implementation is implied.
