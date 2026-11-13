# ADR-0021: User interface

- **Status:** Owner-approved; implementation deferred to the delivery-ecosystem phase.
- **Source decision:** Community-applicable portion of original Ferrum architecture ADR-0021, baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Future Community administrative UI.

## Decision

The MVP does not include a web UI. The initial UI scope, when scheduled, covers service and seal status, policy management and viewing, KV browsing/editing, PKI certificate issuance and viewing, lease/token visibility, and audit configuration.

The UI is served from the same server/API. It uses a strict Content Security Policy, does not persist secrets in `localStorage`, uses short-lived administrative sessions and does not perform sensitive cryptography in the browser.

The initial technology direction is Rust with Leptos/WASM. Re-evaluate framework maturity, accessibility and maintenance cost when the UI phase begins.

## Security considerations

A UI never replaces server-side authorization. Every action uses the same authentication, ACL, resource limits and audit controls as the API.
