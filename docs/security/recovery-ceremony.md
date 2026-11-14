# Offline root ceremony and recovery (Phase 1.3)

**Scope:** Community edition, single logical tenant (`tenant_id=root`). This runbook covers offline creation and custody of Shamir recovery shares. It does not implement bootstrap, seal/unseal, generate-root quorum, backups, AWS KMS or an online recovery API.

## Approved policy

The default is **5 shares / threshold 3**. Both numbers are configurable. Community rejects thresholds below 2 and share counts above 255 (the GF(256) participant identifier space). The exact generate-root quorum is still pending and is not selected or implied by this runbook.

The root secret length is deliberately supplied by the caller. This phase does not invent a key-hierarchy root size. The caller must use the length approved for the key being created.

## Ceremony prerequisites

- Use a dedicated host booted from a verified, access-controlled image. Verify the Ferrum Community source release and build provenance before disconnecting it from untrusted networks.
- Conduct the ceremony offline. Disable network interfaces, remote administration, cloud clipboard/sync, screen capture, telemetry and terminal/session recording. Do not run CI, an IDE extension or an assistant against ceremony memory.
- Identify the selected custodians in advance. Each custodian must receive one distinct participant share, and custodians must not share their envelopes or storage location.
- Prepare individually sealed, tamper-evident physical envelopes and separate secure storage locations. Do not place all shares in one safe, office, backup set or administrator account.
- Agree the required secret length and the `RecoveryPolicy` before generating any material. Record the non-secret policy decision and ceremony date in the custody record; do not record shares, the root, the HMAC check key or their byte encodings.

## Create and distribute shares

1. Start the offline ceremony tool using the reviewed Community build. The recovery library itself performs no filesystem, network, database, logging or service-storage operations.
2. Call `generate_secret_shares(secret_len, policy)` to generate root material from an OS-seeded CSPRNG and split it. The library returns only `RecoveryShare` values; it does not return or persist the root.
3. Hand one share directly to each named custodian. Reveal only that custodian's share during the handoff. Do not paste it into a ticket, chat, email, shell history, clipboard manager, log, screenshot, recording, fixture, CI artifact, crash report or service database.
4. Each custodian seals the share immediately and stores it at their assigned physically separate location. Record custody identity and envelope handling events without recording share contents.
5. Before ending the ceremony, have the required threshold of distinct custodians verify that their shares belong to the same ceremony and can reconstruct the result. Use the recovery API in the same offline environment. The reconstructed buffer is zeroizing; destroy any additional application or terminal copies and do not print the recovered root.
6. Shut down the ceremony host after best-effort memory cleanup. Zeroization cannot guarantee removal of every copy in registers, swap, firmware or diagnostic state; do not claim absolute memory protection.

## Recover

1. Convene at least the configured threshold of distinct custodians. Collect shares from the same ceremony only; confirm public policy and participant identifiers without exposing their bytes.
2. Pass the shares to `recover_secret`. The function rejects malformed formats, unsupported versions, duplicate participant identifiers, mixed ceremonies/policies and insufficient shares.
3. Recovery reconstructs the protected payload and verifies an HMAC-SHA-256 integrity tag before returning root bytes. A failed verification returns no root plaintext.
4. Use the returned `Zeroizing<Vec<u8>>` only in the authorized offline recovery workflow. Never log or display it. Do not persist shares or root material in the Community service.
5. Return each share to its custodian and reseal it. Record identities, time, reason and outcome only; no share content or root material.

If fewer than the threshold of valid shares remain, recovery is unavailable; there is no threshold bypass. If shares appear altered, mixed or compromised, stop and investigate rather than weakening validation or editing bytes.

## Format and integrity properties

FRS1 contains a fixed-version header, a random ceremony identifier, public threshold/share-count metadata, the original root length, an integrity tag and one Shamir share. The verification key is itself included in the Shamir-protected payload. After reconstruction, HMAC authenticates the header and root before any root bytes are returned.

This integrity tag is not a digital signature, does not identify a custodian, and does not verify each share independently. It detects malformed or corrupted reconstruction results under the Shamir threshold assumption. Physical custody and authenticated out-of-band transfer remain necessary.

The share wrapper is intentionally not Serde-serializable and has redacted `Debug`. Explicit byte access exists only for offline handoff. Copies made outside the type are the caller's responsibility.

## Evidence and limits

- Unit tests exercise all 10 possible 3-of-5 subsets, insufficient thresholds, duplicates, cross-ceremony mixing, byte mutation, malformed/truncated/trailing envelopes and debug redaction.
- Fuzz targets cover arbitrary FRS1 parser input and mutated Shamir share sets. The corpus contains only malformed non-share prefixes and generic fuzz inputs; it does not contain a valid recovery share or root fixture.
- The recovery crate has no service-storage dependency or I/O path. This is code-boundary evidence, not a runtime deployment proof.
- The crate reuses the upstream `vsss-rs` GF(256) implementation. Miri is not used as an oracle for the AWS-LC HMAC FFI path; Miri remains enabled for the pure-Rust KMP parser. No custom finite-field implementation is introduced.
- Full independent cryptographic review remains required before production use. This phase does not authorize production recovery or replace an external security audit.
