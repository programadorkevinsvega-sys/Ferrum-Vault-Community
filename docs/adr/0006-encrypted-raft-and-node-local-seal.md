# ADR-0006: Encrypted Raft and node-local seal state

- **Status:** Owner-approved; implementation deferred to the high-availability phase.
- **Source decision:** Original Ferrum architecture ADR-0006, owner-approved baseline commit `1fba2e2ab599ee2952a0e7e10a6dba78a66bfb79`.
- **Scope:** Community high-availability architecture.

## Decision

The encryption barrier sits above Raft. Raft logs and snapshots contain ciphertext and minimum required metadata only. The selected Raft implementation is `openraft`. Nodes authenticate using mTLS with a dedicated private CA.

Seal state is local to each node and is never replicated. The initial node is configured explicitly. Adding a node requires an explicit join request, mTLS authentication and approval by an authorized operator. Automatic discovery and automatic admission are not allowed.

In a future cluster, nonce/key-use budgets are coordinated through Raft. Reserved blocks are never reused after failure or leadership change.

## Security considerations

A replicated boolean or another node's state is never proof that the local node is unsealed. Each node verifies its own cryptographic material and integrity before serving protected operations. Tests must inspect logs and snapshots for plaintext and cover stale nodes, untrusted certificates and unapproved joins.
