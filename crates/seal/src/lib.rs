#![forbid(unsafe_code)]

//! Process-local seal lifecycle and one-time bootstrap state machine.
//!
//! The controller keeps the recovered root only while unsealed. It does not
//! persist state, implement an HTTP API, or provide the Phase 1.5 auto-unseal
//! adapter. A durable repository is required before this state machine can be
//! used by a multi-process or production service.

use std::fmt;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{self, Context};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use ferrum_recovery::{RecoveryPolicy, RecoveryShare, recover_secret};
use zeroize::Zeroizing;

const BOOTSTRAP_TOKEN_LEN: usize = 32;
const BOOTSTRAP_TOKEN_DOMAIN: &[u8] = b"Ferrum Community bootstrap token verifier v1\0";

/// Current lifecycle state of the Community vault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealStatus {
    /// No root recovery ceremony has been bound to this controller.
    Uninitialized,
    /// A recovery ceremony is configured, but its root is not held in memory.
    Sealed,
    /// The matching recovery quorum was verified and the root is held in memory.
    Unsealed,
}

/// Non-secret, read-only view of the lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealSnapshot {
    pub status: SealStatus,
    pub generation: u64,
    pub bootstrap_pending: bool,
    pub bootstrap_consumed: bool,
}

/// Explicit M-of-N authorization policy for operations on the root key.
///
/// There is deliberately no Default implementation. A controller starts with
/// no root-operation quorum and rejects privileged operations until a valid
/// policy is configured explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootQuorumPolicy {
    threshold: usize,
    share_count: usize,
}

impl RootQuorumPolicy {
    pub fn new(threshold: usize, share_count: usize) -> Result<Self, SealError> {
        if threshold < 2 || share_count < threshold || share_count > 255 {
            return Err(SealError::InvalidQuorumPolicy);
        }
        Ok(Self {
            threshold,
            share_count,
        })
    }

    pub const fn threshold(self) -> usize {
        self.threshold
    }

    pub const fn share_count(self) -> usize {
        self.share_count
    }

    fn matches(self, recovery_policy: RecoveryPolicy) -> bool {
        self.threshold == recovery_policy.threshold()
            && self.share_count == recovery_policy.share_count()
    }
}

/// Root operations that require the configured root quorum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootQuorumOperation {
    GenerateRoot,
    RotateRoot,
    RevokeRoot,
}

/// Non-secret context supplied to a quorum-authorized operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootQuorumContext {
    pub operation: RootQuorumOperation,
    pub ceremony_id: [u8; 16],
    pub generation: u64,
}

/// A 256-bit one-time bootstrap credential.
///
/// It is intentionally not Clone, Serialize, Display or persistable through
/// this crate. Debug output is redacted. Call as_bytes only for the explicit
/// out-of-band handoff to the bootstrap operator.
pub struct BootstrapToken {
    bytes: Zeroizing<[u8; BOOTSTRAP_TOKEN_LEN]>,
}

impl BootstrapToken {
    /// Parses a bootstrap credential received from the operator.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SealError> {
        let value: [u8; BOOTSTRAP_TOKEN_LEN] = bytes
            .try_into()
            .map_err(|_| SealError::InvalidBootstrapTokenLength)?;
        Ok(Self {
            bytes: Zeroizing::new(value),
        })
    }

    /// Exposes the credential bytes for an explicit secure handoff.
    pub fn as_bytes(&self) -> &[u8; BOOTSTRAP_TOKEN_LEN] {
        &self.bytes
    }

    fn generate() -> Result<Self, SealError> {
        let mut bytes = Zeroizing::new([0_u8; BOOTSTRAP_TOKEN_LEN]);
        SystemRandom::new()
            .fill(&mut *bytes)
            .map_err(|_| SealError::RandomnessUnavailable)?;
        Ok(Self { bytes })
    }
}

impl fmt::Debug for BootstrapToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapToken")
            .field("redacted", &true)
            .field("length", &BOOTSTRAP_TOKEN_LEN)
            .finish()
    }
}

/// Errors from the seal lifecycle. Display text never contains token or root
/// material. Bootstrap credential failures deliberately share one public
/// error to avoid exposing whether a token was absent, expired, consumed or
/// incorrect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealError {
    InvalidStateTransition,
    BootstrapAlreadyPending,
    BootstrapRejected,
    InvalidBootstrapTokenLength,
    InvalidBootstrapLifetime,
    BootstrapExpiryOutOfRange,
    UnsealRejected,
    ConcurrentTransition,
    RandomnessUnavailable,
    GenerationExhausted,
    QuorumNotConfigured,
    InvalidQuorumPolicy,
    RootQuorumRejected,
}

impl fmt::Display for SealError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidStateTransition => "seal lifecycle transition is not allowed",
            Self::BootstrapAlreadyPending => "a bootstrap credential is already pending",
            Self::BootstrapRejected => "bootstrap credential rejected",
            Self::InvalidBootstrapTokenLength => "invalid bootstrap credential length",
            Self::InvalidBootstrapLifetime => "bootstrap credential lifetime must be positive",
            Self::BootstrapExpiryOutOfRange => "bootstrap credential expiry is out of range",
            Self::UnsealRejected => "unseal request rejected",
            Self::ConcurrentTransition => "seal lifecycle changed during the operation",
            Self::RandomnessUnavailable => "secure randomness is unavailable",
            Self::GenerationExhausted => "seal lifecycle generation exhausted",
            Self::QuorumNotConfigured => "root operation quorum is not configured",
            Self::InvalidQuorumPolicy => "invalid root operation quorum policy",
            Self::RootQuorumRejected => "root operation quorum rejected",
        })
    }
}

impl std::error::Error for SealError {}

struct PendingBootstrap {
    verifier: [u8; digest::SHA256_OUTPUT_LEN],
    expires_at: Instant,
}

struct Inner {
    status: SealStatus,
    generation: u64,
    bootstrap: Option<PendingBootstrap>,
    bootstrap_consumed: bool,
    recovery_ceremony_id: Option<[u8; 16]>,
    recovery_policy: Option<RecoveryPolicy>,
    root_quorum: Option<RootQuorumPolicy>,
    active_root: Option<Zeroizing<Vec<u8>>>,
}

/// Thread-safe process-local seal state machine.
///
/// SealController serializes transitions in one process and uses a generation
/// check around recovery work so concurrent bootstrap/unseal attempts cannot
/// both commit. Its state is volatile: it is not a substitute for the durable,
/// transactional repository that will be introduced with Phase 1.7.
pub struct SealController {
    inner: Mutex<Inner>,
}

impl Default for SealController {
    fn default() -> Self {
        Self::new()
    }
}

impl SealController {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                status: SealStatus::Uninitialized,
                generation: 0,
                bootstrap: None,
                bootstrap_consumed: false,
                recovery_ceremony_id: None,
                recovery_policy: None,
                root_quorum: None,
                active_root: None,
            }),
        }
    }

    /// Returns a non-secret lifecycle snapshot.
    pub fn snapshot(&self) -> SealSnapshot {
        let inner = self.lock();
        SealSnapshot {
            status: inner.status,
            generation: inner.generation,
            bootstrap_pending: inner.bootstrap.is_some(),
            bootstrap_consumed: inner.bootstrap_consumed,
        }
    }

    /// Installs an explicit M-of-N root-operation policy. There is no default.
    ///
    /// If a recovery ceremony has already been bound, its FRS1 policy must
    /// match exactly. This prevents a 5/3 recovery set from silently being
    /// treated as the separately approved 2/3 root-operation quorum.
    pub fn configure_root_quorum(&self, policy: RootQuorumPolicy) -> Result<(), SealError> {
        let mut inner = self.lock();
        if inner.root_quorum == Some(policy) {
            return Ok(());
        }
        if inner.root_quorum.is_some()
            || inner
                .recovery_policy
                .is_some_and(|recovery| !policy.matches(recovery))
        {
            return Err(SealError::InvalidQuorumPolicy);
        }
        let next = next_generation(inner.generation)?;
        inner.root_quorum = Some(policy);
        inner.generation = next;
        Ok(())
    }

    /// Issues a one-time bootstrap credential with a caller-selected lifetime.
    ///
    /// There is deliberately no default TTL. Expiry uses Instant, not wall
    /// clock time. An expired, unused credential may be replaced while the
    /// controller remains uninitialized; a consumed credential may not.
    pub fn issue_bootstrap_token(&self, lifetime: Duration) -> Result<BootstrapToken, SealError> {
        self.issue_bootstrap_token_at(lifetime, Instant::now())
    }

    fn issue_bootstrap_token_at(
        &self,
        lifetime: Duration,
        now: Instant,
    ) -> Result<BootstrapToken, SealError> {
        if lifetime.is_zero() {
            return Err(SealError::InvalidBootstrapLifetime);
        }
        let expires_at = now
            .checked_add(lifetime)
            .ok_or(SealError::BootstrapExpiryOutOfRange)?;
        let token = BootstrapToken::generate()?;
        let verifier = token_verifier(token.as_bytes());

        let mut inner = self.lock();
        if inner.status != SealStatus::Uninitialized || inner.bootstrap_consumed {
            return Err(SealError::InvalidStateTransition);
        }
        if inner
            .bootstrap
            .as_ref()
            .is_some_and(|pending| now < pending.expires_at)
        {
            return Err(SealError::BootstrapAlreadyPending);
        }

        let next_generation = next_generation(inner.generation)?;
        inner.bootstrap = Some(PendingBootstrap {
            verifier,
            expires_at,
        });
        inner.generation = next_generation;
        Ok(token)
    }

    /// Completes bootstrap using a valid, same-ceremony Shamir threshold.
    ///
    /// The recovered root is verified by ferrum-recovery and immediately
    /// dropped. Only the non-secret FRS1 ceremony identifier is retained.
    /// The bootstrap token is consumed atomically with the state transition.
    pub fn bootstrap(
        &self,
        token: &BootstrapToken,
        shares: &[RecoveryShare],
    ) -> Result<(), SealError> {
        self.bootstrap_with_clock(token, shares, Instant::now)
    }

    fn bootstrap_with_clock<F>(
        &self,
        token: &BootstrapToken,
        shares: &[RecoveryShare],
        now: F,
    ) -> Result<(), SealError>
    where
        F: Fn() -> Instant,
    {
        let supplied_verifier = token_verifier(token.as_bytes());
        let (expected_verifier, expected_generation) = {
            let mut inner = self.lock();
            if inner.status != SealStatus::Uninitialized || inner.bootstrap_consumed {
                return Err(SealError::BootstrapRejected);
            }
            let Some(pending) = inner.bootstrap.as_ref() else {
                return Err(SealError::BootstrapRejected);
            };
            if now() >= pending.expires_at {
                let next = next_generation(inner.generation)?;
                inner.bootstrap = None;
                inner.generation = next;
                return Err(SealError::BootstrapRejected);
            }
            if !constant_time_equal(&supplied_verifier, &pending.verifier) {
                return Err(SealError::BootstrapRejected);
            }
            (pending.verifier, inner.generation)
        };

        let ceremony_id = matching_ceremony_id(shares).ok_or(SealError::BootstrapRejected)?;
        let recovery_policy = shares
            .first()
            .map(RecoveryShare::policy)
            .ok_or(SealError::BootstrapRejected)?;
        {
            let inner = self.lock();
            if inner
                .root_quorum
                .is_some_and(|policy| !policy.matches(recovery_policy))
            {
                return Err(SealError::BootstrapRejected);
            }
        }
        let recovered = recover_secret(shares).map_err(|_| SealError::BootstrapRejected)?;
        drop(recovered);

        let mut inner = self.lock();
        if inner.status != SealStatus::Uninitialized
            || inner.bootstrap_consumed
            || inner.generation != expected_generation
        {
            return Err(SealError::ConcurrentTransition);
        }
        let Some(pending) = inner.bootstrap.as_ref() else {
            return Err(SealError::ConcurrentTransition);
        };
        if !constant_time_equal(&expected_verifier, &pending.verifier) {
            return Err(SealError::ConcurrentTransition);
        }
        if now() >= pending.expires_at {
            let next = next_generation(inner.generation)?;
            inner.bootstrap = None;
            inner.generation = next;
            return Err(SealError::BootstrapRejected);
        }

        if inner
            .root_quorum
            .is_some_and(|policy| !policy.matches(recovery_policy))
        {
            return Err(SealError::BootstrapRejected);
        }
        let next = next_generation(inner.generation)?;
        inner.recovery_ceremony_id = Some(ceremony_id);
        inner.recovery_policy = Some(recovery_policy);
        inner.bootstrap = None;
        inner.bootstrap_consumed = true;
        inner.active_root = None;
        inner.status = SealStatus::Sealed;
        inner.generation = next;
        Ok(())
    }

    /// Unseals only when the supplied shares reconstruct the configured
    /// recovery ceremony. The recovered root remains in a zeroizing buffer
    /// inside this controller until seal is called.
    pub fn unseal(&self, shares: &[RecoveryShare]) -> Result<(), SealError> {
        let (expected_ceremony_id, expected_generation) = {
            let inner = self.lock();
            if inner.status != SealStatus::Sealed {
                return Err(SealError::InvalidStateTransition);
            }
            (
                inner
                    .recovery_ceremony_id
                    .ok_or(SealError::UnsealRejected)?,
                inner.generation,
            )
        };

        let supplied_ceremony_id = matching_ceremony_id(shares).ok_or(SealError::UnsealRejected)?;
        if !constant_time_equal(&expected_ceremony_id, &supplied_ceremony_id) {
            return Err(SealError::UnsealRejected);
        }
        let recovered = recover_secret(shares).map_err(|_| SealError::UnsealRejected)?;

        let mut inner = self.lock();
        if inner.status != SealStatus::Sealed || inner.generation != expected_generation {
            return Err(SealError::ConcurrentTransition);
        }
        if !inner
            .recovery_ceremony_id
            .is_some_and(|expected| constant_time_equal(&expected, &supplied_ceremony_id))
        {
            return Err(SealError::UnsealRejected);
        }

        let next = next_generation(inner.generation)?;
        inner.active_root = Some(recovered);
        inner.status = SealStatus::Unsealed;
        inner.generation = next;
        Ok(())
    }

    /// Seals the controller and drops its in-memory root buffer.
    pub fn seal(&self) -> Result<(), SealError> {
        let root_to_clear = {
            let mut inner = self.lock();
            if inner.status != SealStatus::Unsealed {
                return Err(SealError::InvalidStateTransition);
            }
            let next = next_generation(inner.generation)?;
            inner.status = SealStatus::Sealed;
            inner.generation = next;
            inner.active_root.take()
        };
        drop(root_to_clear);
        Ok(())
    }

    /// Provides scoped access to the active root without returning or cloning
    /// its buffer. Callers must not retain or copy the supplied bytes.
    pub fn with_root_key<T>(&self, operation: impl FnOnce(&[u8]) -> T) -> Result<T, SealError> {
        let inner = self.lock();
        if inner.status != SealStatus::Unsealed {
            return Err(SealError::InvalidStateTransition);
        }
        let root = inner
            .active_root
            .as_ref()
            .ok_or(SealError::InvalidStateTransition)?;
        Ok(operation(root.as_slice()))
    }

    /// Runs a root operation only after validating the configured M-of-N
    /// quorum against the controller's currently bound FRS1 root ceremony.
    ///
    /// The FRS1 header must declare exactly the configured M and N; at least M
    /// and at most N distinct shares must be supplied. The recovery function
    /// verifies ceremony consistency and the integrity tag. The reconstructed
    /// root is zeroizing and is dropped before the callback. Neither root bytes
    /// nor share bytes are exposed to or retained by the callback.
    ///
    /// This is an in-process authorization boundary. The callback performs the
    /// operation-specific work while the controller lock is held and must not
    /// re-enter this controller. Durable mutation and audit transactions belong
    /// to service/storage integration phases.
    pub fn with_root_quorum<T>(
        &self,
        operation: RootQuorumOperation,
        shares: &[RecoveryShare],
        action: impl FnOnce(RootQuorumContext) -> T,
    ) -> Result<T, SealError> {
        let (policy, expected_ceremony_id, expected_generation) = {
            let inner = self.lock();
            if inner.status == SealStatus::Uninitialized {
                return Err(SealError::RootQuorumRejected);
            }
            let policy = inner.root_quorum.ok_or(SealError::QuorumNotConfigured)?;
            let ceremony_id = inner
                .recovery_ceremony_id
                .ok_or(SealError::RootQuorumRejected)?;
            (policy, ceremony_id, inner.generation)
        };

        if shares.len() < policy.threshold()
            || shares.len() > policy.share_count()
            || shares
                .first()
                .is_none_or(|share| !policy.matches(share.policy()))
        {
            return Err(SealError::RootQuorumRejected);
        }

        let supplied_ceremony_id =
            matching_ceremony_id(shares).ok_or(SealError::RootQuorumRejected)?;
        if !constant_time_equal(&expected_ceremony_id, &supplied_ceremony_id) {
            return Err(SealError::RootQuorumRejected);
        }
        let recovered = recover_secret(shares).map_err(|_| SealError::RootQuorumRejected)?;
        drop(recovered);

        let inner = self.lock();
        if inner.status == SealStatus::Uninitialized
            || inner.generation != expected_generation
            || !inner
                .recovery_ceremony_id
                .is_some_and(|expected| constant_time_equal(&expected, &supplied_ceremony_id))
        {
            return Err(SealError::ConcurrentTransition);
        }
        let context = RootQuorumContext {
            operation,
            ceremony_id: supplied_ceremony_id,
            generation: inner.generation,
        };
        Ok(action(context))
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // Recovering the guard after a caller panic keeps seal available to
        // clear the zeroizing root buffer rather than permanently locking it.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn matching_ceremony_id(shares: &[RecoveryShare]) -> Option<[u8; 16]> {
    let first = shares.first()?;
    let ceremony_id = first.ceremony_id();
    if shares
        .iter()
        .any(|share| !constant_time_equal(&ceremony_id, &share.ceremony_id()))
    {
        return None;
    }
    Some(ceremony_id)
}

fn token_verifier(token: &[u8; BOOTSTRAP_TOKEN_LEN]) -> [u8; digest::SHA256_OUTPUT_LEN] {
    digest_bytes(BOOTSTRAP_TOKEN_DOMAIN, token)
}

fn digest_bytes(domain: &[u8], value: &[u8]) -> [u8; digest::SHA256_OUTPUT_LEN] {
    let mut context = Context::new(&digest::SHA256);
    context.update(domain);
    context.update(&(value.len() as u64).to_be_bytes());
    context.update(value);
    let digest = context.finish();
    let mut output = [0_u8; digest::SHA256_OUTPUT_LEN];
    output.copy_from_slice(digest.as_ref());
    output
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    verify_slices_are_equal(left, right).is_ok()
}

fn next_generation(current: u64) -> Result<u64, SealError> {
    current.checked_add(1).ok_or(SealError::GenerationExhausted)
}

/// Outcomes recorded for revocation of a credential derived from the root.
/// Credential revocation does not require root shares, but must be audited.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRevocationOutcome {
    Requested,
    Succeeded,
    Failed,
}

/// Non-secret audit record. The raw credential reference is never exposed;
/// only a domain-separated SHA-256 fingerprint is sent to the audit sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialRevocationAuditEvent {
    pub credential_fingerprint: [u8; digest::SHA256_OUTPUT_LEN],
    pub outcome: CredentialRevocationOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditSinkError {
    Unavailable,
}

/// The caller must provide the service's audit sink. There is no silent or
/// process-local default sink.
pub trait AuditSink: Send + Sync {
    fn record(&self, event: CredentialRevocationAuditEvent) -> Result<(), AuditSinkError>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum CredentialRevocationError<E> {
    EmptyCredentialReference,
    AuditUnavailableBeforeRevocation,
    RevocationFailed(E),
    RevocationFailedAndAuditUnavailable(E),
    AuditUnavailableAfterRevocation,
}

/// Executes derived-credential revocation without root quorum, but only after
/// the audit sink has accepted a request event. The result is also audited.
pub fn revoke_derived_credential<T, E>(
    credential_reference: &[u8],
    audit_sink: &impl AuditSink,
    revoke: impl FnOnce() -> Result<T, E>,
) -> Result<T, CredentialRevocationError<E>> {
    if credential_reference.is_empty() {
        return Err(CredentialRevocationError::EmptyCredentialReference);
    }
    let fingerprint = digest_bytes(
        b"Ferrum Community derived credential audit fingerprint v1\0",
        credential_reference,
    );
    audit_sink
        .record(CredentialRevocationAuditEvent {
            credential_fingerprint: fingerprint,
            outcome: CredentialRevocationOutcome::Requested,
        })
        .map_err(|_| CredentialRevocationError::AuditUnavailableBeforeRevocation)?;

    match revoke() {
        Ok(value) => {
            audit_sink
                .record(CredentialRevocationAuditEvent {
                    credential_fingerprint: fingerprint,
                    outcome: CredentialRevocationOutcome::Succeeded,
                })
                .map_err(|_| CredentialRevocationError::AuditUnavailableAfterRevocation)?;
            Ok(value)
        }
        Err(error) => {
            if audit_sink
                .record(CredentialRevocationAuditEvent {
                    credential_fingerprint: fingerprint,
                    outcome: CredentialRevocationOutcome::Failed,
                })
                .is_err()
            {
                Err(CredentialRevocationError::RevocationFailedAndAuditUnavailable(error))
            } else {
                Err(CredentialRevocationError::RevocationFailed(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuditSink, AuditSinkError, BootstrapToken, CredentialRevocationAuditEvent,
        CredentialRevocationError, CredentialRevocationOutcome, RootQuorumOperation,
        RootQuorumPolicy, SealController, SealError, SealStatus, revoke_derived_credential,
    };
    use ferrum_recovery::{RecoveryPolicy, RecoveryShare, split_secret};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    fn shares(root: &[u8]) -> Vec<RecoveryShare> {
        split_secret(root, RecoveryPolicy::default()).expect("split test root")
    }

    fn copy_shares(source: &[RecoveryShare]) -> Vec<RecoveryShare> {
        source
            .iter()
            .map(|share| RecoveryShare::decode(share.as_bytes()).expect("copy test share"))
            .collect()
    }

    #[test]
    fn bootstrap_requires_a_positive_explicit_lifetime() {
        let controller = SealController::new();
        assert_eq!(
            controller.issue_bootstrap_token(Duration::ZERO).err(),
            Some(SealError::InvalidBootstrapLifetime)
        );
        assert_eq!(controller.snapshot().status, SealStatus::Uninitialized);
    }

    #[test]
    fn a_live_bootstrap_token_cannot_be_replaced() {
        let controller = SealController::new();
        let token = controller
            .issue_bootstrap_token(Duration::from_secs(60))
            .expect("issue token");
        assert!(format!("{token:?}").contains("redacted"));
        assert_eq!(
            controller
                .issue_bootstrap_token(Duration::from_secs(60))
                .err(),
            Some(SealError::BootstrapAlreadyPending)
        );
        assert!(controller.snapshot().bootstrap_pending);
    }

    #[test]
    fn expired_bootstrap_token_is_rejected_and_can_be_reissued() {
        let controller = SealController::new();
        let issued_at = Instant::now();
        let token = controller
            .issue_bootstrap_token_at(Duration::from_secs(5), issued_at)
            .expect("issue token");
        let root_shares = shares(b"synthetic root for expiry test");
        let expired_at = issued_at + Duration::from_secs(5);

        assert_eq!(
            controller
                .bootstrap_with_clock(&token, &root_shares, || expired_at)
                .err(),
            Some(SealError::BootstrapRejected)
        );
        assert_eq!(controller.snapshot().status, SealStatus::Uninitialized);
        assert!(!controller.snapshot().bootstrap_pending);

        assert!(
            controller
                .issue_bootstrap_token_at(Duration::from_secs(5), expired_at)
                .is_ok()
        );
    }

    #[test]
    fn wrong_token_does_not_consume_the_valid_credential() {
        let controller = SealController::new();
        let token = controller
            .issue_bootstrap_token(Duration::from_secs(60))
            .expect("issue token");
        let wrong = BootstrapToken::from_bytes(&[0xA5; 32]).expect("parse token bytes");
        let root_shares = shares(b"synthetic root for token test");

        assert_eq!(
            controller.bootstrap(&wrong, &root_shares).err(),
            Some(SealError::BootstrapRejected)
        );
        assert!(controller.snapshot().bootstrap_pending);
        controller
            .bootstrap(&token, &root_shares)
            .expect("valid token bootstraps");
    }

    #[test]
    fn bootstrap_consumes_token_and_binds_one_recovery_ceremony() {
        let controller = SealController::new();
        let token = controller
            .issue_bootstrap_token(Duration::from_secs(60))
            .expect("issue token");
        let root_shares = shares(b"synthetic root for bootstrap test");

        controller
            .bootstrap(&token, &root_shares[..3])
            .expect("bootstrap with threshold shares");
        let snapshot = controller.snapshot();
        assert_eq!(snapshot.status, SealStatus::Sealed);
        assert!(snapshot.bootstrap_consumed);
        assert!(!snapshot.bootstrap_pending);
        assert_eq!(
            controller.bootstrap(&token, &root_shares),
            Err(SealError::BootstrapRejected)
        );
        assert_eq!(
            controller
                .issue_bootstrap_token(Duration::from_secs(60))
                .err(),
            Some(SealError::InvalidStateTransition)
        );
    }

    #[test]
    fn failed_recovery_does_not_initialize_or_consume_bootstrap() {
        let controller = SealController::new();
        let token = controller
            .issue_bootstrap_token(Duration::from_secs(60))
            .expect("issue token");
        let root_shares = shares(b"synthetic root for recovery test");
        let other_shares = shares(b"different synthetic ceremony");

        assert_eq!(
            controller.bootstrap(&token, &other_shares[..2]),
            Err(SealError::BootstrapRejected)
        );
        assert_eq!(controller.snapshot().status, SealStatus::Uninitialized);
        assert!(controller.snapshot().bootstrap_pending);

        controller
            .bootstrap(&token, &root_shares[..3])
            .expect("valid shares remain usable");
    }

    #[test]
    fn unseal_rejects_a_different_ceremony_and_stays_sealed() {
        let controller = SealController::new();
        let token = controller
            .issue_bootstrap_token(Duration::from_secs(60))
            .expect("issue token");
        let original = shares(b"original root");
        let other = shares(b"unrelated root");
        controller
            .bootstrap(&token, &original[..3])
            .expect("bootstrap");

        assert_eq!(
            controller.unseal(&other[..3]),
            Err(SealError::UnsealRejected)
        );
        assert_eq!(controller.snapshot().status, SealStatus::Sealed);
    }

    #[test]
    fn unseal_holds_root_only_until_seal() {
        let controller = SealController::new();
        let root = b"synthetic root held only while unsealed";
        let root_shares = shares(root);
        let token = controller
            .issue_bootstrap_token(Duration::from_secs(60))
            .expect("issue token");
        controller
            .bootstrap(&token, &root_shares[..3])
            .expect("bootstrap");

        assert_eq!(
            controller.with_root_key(|bytes| bytes.to_vec()),
            Err(SealError::InvalidStateTransition)
        );
        controller
            .unseal(&root_shares[1..4])
            .expect("unseal with another threshold subset");
        assert_eq!(
            controller
                .with_root_key(|bytes| bytes.to_vec())
                .expect("root available"),
            root.to_vec()
        );

        controller.seal().expect("seal");
        assert_eq!(controller.snapshot().status, SealStatus::Sealed);
        assert_eq!(
            controller.with_root_key(|_| ()),
            Err(SealError::InvalidStateTransition)
        );
        assert_eq!(controller.seal(), Err(SealError::InvalidStateTransition));
    }

    #[test]
    fn concurrent_bootstrap_replay_has_exactly_one_winner() {
        let controller = Arc::new(SealController::new());
        let token = controller
            .issue_bootstrap_token(Duration::from_secs(60))
            .expect("issue token");
        let token_copy = BootstrapToken::from_bytes(token.as_bytes()).expect("copy token");
        let root_shares = shares(b"synthetic root for concurrent bootstrap");
        let barrier = Arc::new(Barrier::new(3));

        let first_controller = Arc::clone(&controller);
        let first_barrier = Arc::clone(&barrier);
        let first_shares = copy_shares(&root_shares[..3]);
        let first = thread::spawn(move || {
            first_barrier.wait();
            first_controller.bootstrap(&token, &first_shares).is_ok()
        });

        let second_controller = Arc::clone(&controller);
        let second_barrier = Arc::clone(&barrier);
        let second_shares = copy_shares(&root_shares[..3]);
        let second = thread::spawn(move || {
            second_barrier.wait();
            second_controller
                .bootstrap(&token_copy, &second_shares)
                .is_ok()
        });

        barrier.wait();
        let first_won = if first.join().expect("first thread") {
            1
        } else {
            0
        };
        let second_won = if second.join().expect("second thread") {
            1
        } else {
            0
        };
        let winners = first_won + second_won;
        assert_eq!(winners, 1);
        assert_eq!(controller.snapshot().status, SealStatus::Sealed);
    }

    #[test]
    fn concurrent_unseal_has_exactly_one_winner() {
        let controller = Arc::new(SealController::new());
        let root_shares = shares(b"synthetic root for concurrent unseal");
        let token = controller
            .issue_bootstrap_token(Duration::from_secs(60))
            .expect("issue token");
        controller
            .bootstrap(&token, &root_shares[..3])
            .expect("bootstrap");
        let barrier = Arc::new(Barrier::new(3));

        let first_controller = Arc::clone(&controller);
        let first_barrier = Arc::clone(&barrier);
        let first_shares = copy_shares(&root_shares[..3]);
        let first = thread::spawn(move || {
            first_barrier.wait();
            first_controller.unseal(&first_shares).is_ok()
        });

        let second_controller = Arc::clone(&controller);
        let second_barrier = Arc::clone(&barrier);
        let second_shares = copy_shares(&root_shares[..3]);
        let second = thread::spawn(move || {
            second_barrier.wait();
            second_controller.unseal(&second_shares).is_ok()
        });

        barrier.wait();
        let first_won = if first.join().expect("first thread") {
            1
        } else {
            0
        };
        let second_won = if second.join().expect("second thread") {
            1
        } else {
            0
        };
        let winners = first_won + second_won;
        assert_eq!(winners, 1);
        assert_eq!(controller.snapshot().status, SealStatus::Unsealed);
        controller.seal().expect("seal after concurrent test");
    }

    #[test]
    fn deterministic_property_sweep_covers_root_lengths_and_subsets() {
        for length in 1..=32 {
            let root: Vec<u8> = (0..length)
                .map(|index| (index as u8).wrapping_mul(31).wrapping_add(length as u8))
                .collect();
            let root_shares = shares(&root);
            let controller = SealController::new();
            let token = controller
                .issue_bootstrap_token_at(Duration::from_secs(60), Instant::now())
                .expect("issue random token");
            controller
                .bootstrap(&token, &root_shares[..3])
                .expect("bootstrap generated shares");
            controller
                .unseal(&root_shares[(length % 3)..(length % 3 + 3)])
                .expect("unseal generated shares");
            assert_eq!(
                controller.with_root_key(|bytes| bytes.to_vec()).unwrap(),
                root
            );
            controller.seal().expect("seal after property case");
        }
    }

    #[test]
    fn a_panic_in_scoped_root_use_does_not_permanently_lock_seal() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let controller = SealController::new();
        let root_shares = shares(b"synthetic root for poison recovery");
        let token = controller
            .issue_bootstrap_token(Duration::from_secs(60))
            .expect("issue token");
        controller
            .bootstrap(&token, &root_shares[..3])
            .expect("bootstrap");
        controller.unseal(&root_shares[..3]).expect("unseal");

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = controller.with_root_key(|_| panic!("synthetic caller panic"));
        }));
        assert!(panic.is_err());
        controller.seal().expect("seal remains available");
        assert_eq!(controller.snapshot().status, SealStatus::Sealed);
    }
    fn quorum_shares(root: &[u8]) -> Vec<RecoveryShare> {
        split_secret(root, RecoveryPolicy::new(2, 3).expect("2-of-3 policy"))
            .expect("split quorum root")
    }

    fn configured_quorum_controller(root: &[u8]) -> (SealController, Vec<RecoveryShare>) {
        let controller = SealController::new();
        controller
            .configure_root_quorum(RootQuorumPolicy::new(2, 3).expect("valid root quorum"))
            .expect("configure root quorum");
        let root_shares = quorum_shares(root);
        let token = controller
            .issue_bootstrap_token(Duration::from_secs(60))
            .expect("issue bootstrap token");
        controller
            .bootstrap(&token, &root_shares[..2])
            .expect("bootstrap 2-of-3 root");
        (controller, root_shares)
    }

    #[test]
    fn root_quorum_has_no_default_and_rejects_missing_or_invalid_configuration() {
        let root_shares = quorum_shares(b"synthetic root for missing quorum test");
        let controller = SealController::new();
        let token = controller
            .issue_bootstrap_token(Duration::from_secs(60))
            .expect("issue token");
        controller
            .bootstrap(&token, &root_shares[..2])
            .expect("bootstrap without privileged-operation quorum config");

        assert_eq!(
            controller.with_root_quorum(
                RootQuorumOperation::GenerateRoot,
                &root_shares[..2],
                |_| ()
            ),
            Err(SealError::QuorumNotConfigured)
        );
        assert_eq!(
            RootQuorumPolicy::new(1, 3),
            Err(SealError::InvalidQuorumPolicy)
        );
        assert_eq!(
            RootQuorumPolicy::new(4, 3),
            Err(SealError::InvalidQuorumPolicy)
        );
        assert_eq!(
            controller.with_root_quorum(
                RootQuorumOperation::RotateRoot,
                &root_shares[..2],
                |_| ()
            ),
            Err(SealError::QuorumNotConfigured)
        );
    }

    #[test]
    fn one_fragment_fails_and_two_distinct_fragments_authorize_all_root_operations() {
        let root = b"synthetic root for 2-of-3 operations";
        let (controller, root_shares) = configured_quorum_controller(root);

        for operation in [
            RootQuorumOperation::GenerateRoot,
            RootQuorumOperation::RotateRoot,
            RootQuorumOperation::RevokeRoot,
        ] {
            assert_eq!(
                controller.with_root_quorum(operation, &root_shares[..1], |_| true),
                Err(SealError::RootQuorumRejected),
                "one fragment must not authorize {operation:?}"
            );
            let result = controller
                .with_root_quorum(operation, &root_shares[..2], |context| {
                    assert_eq!(context.operation, operation);
                    assert_eq!(context.ceremony_id, root_shares[0].ceremony_id());
                    true
                })
                .expect("two distinct valid fragments authorize operation");
            assert!(result);
        }
    }

    #[test]
    fn root_quorum_rejects_duplicate_participant_fragments() {
        let (controller, root_shares) =
            configured_quorum_controller(b"synthetic root for duplicate share test");
        let duplicate = [
            RecoveryShare::decode(root_shares[0].as_bytes()).unwrap(),
            RecoveryShare::decode(root_shares[0].as_bytes()).unwrap(),
        ];
        assert_eq!(
            controller.with_root_quorum(RootQuorumOperation::RotateRoot, &duplicate, |_| ()),
            Err(SealError::RootQuorumRejected)
        );
    }

    #[test]
    fn root_quorum_rejects_corrupt_fragments() {
        let (controller, root_shares) =
            configured_quorum_controller(b"synthetic root for corrupted share test");
        let mut corrupted_bytes = root_shares[0].as_bytes().to_vec();
        corrupted_bytes[65] ^= 0x80;
        let corrupted = RecoveryShare::decode(&corrupted_bytes)
            .expect("mutation remains structurally well formed");
        let supplied = [
            corrupted,
            RecoveryShare::decode(root_shares[1].as_bytes()).unwrap(),
        ];
        assert_eq!(
            controller.with_root_quorum(RootQuorumOperation::GenerateRoot, &supplied, |_| ()),
            Err(SealError::RootQuorumRejected)
        );
    }

    #[test]
    fn root_quorum_rejects_fragments_from_another_ceremony() {
        let (controller, first) =
            configured_quorum_controller(b"synthetic root from first ceremony");
        let second = quorum_shares(b"synthetic root from second ceremony");
        let supplied = [
            RecoveryShare::decode(first[0].as_bytes()).unwrap(),
            RecoveryShare::decode(second[1].as_bytes()).unwrap(),
        ];
        assert_eq!(
            controller.with_root_quorum(RootQuorumOperation::RevokeRoot, &supplied, |_| ()),
            Err(SealError::RootQuorumRejected)
        );
    }

    #[test]
    fn the_three_of_five_recovery_default_is_not_accepted_as_the_explicit_2_of_3_root_quorum() {
        let controller = SealController::new();
        controller
            .configure_root_quorum(RootQuorumPolicy::new(2, 3).unwrap())
            .unwrap();
        let default_shares = shares(b"synthetic default 5-of-3 root");
        let token = controller
            .issue_bootstrap_token(Duration::from_secs(60))
            .unwrap();
        assert_eq!(
            controller.bootstrap(&token, &default_shares[..3]),
            Err(SealError::BootstrapRejected)
        );
        assert_eq!(controller.snapshot().status, SealStatus::Uninitialized);
    }

    #[derive(Default)]
    struct TestAuditSink {
        events: Mutex<Vec<CredentialRevocationAuditEvent>>,
        fail: bool,
    }

    impl AuditSink for TestAuditSink {
        fn record(&self, event: CredentialRevocationAuditEvent) -> Result<(), AuditSinkError> {
            if self.fail {
                return Err(AuditSinkError::Unavailable);
            }
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    #[test]
    fn derived_credential_revocation_needs_no_quorum_but_records_audit() {
        let sink = TestAuditSink::default();
        let mut revoked = false;
        let result = revoke_derived_credential(b"credential-reference-123", &sink, || {
            revoked = true;
            Ok::<_, ()>(())
        });
        assert_eq!(result, Ok(()));
        assert!(revoked);
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome, CredentialRevocationOutcome::Requested);
        assert_eq!(events[1].outcome, CredentialRevocationOutcome::Succeeded);
        assert_ne!(events[0].credential_fingerprint, [0_u8; 32]);
    }

    #[test]
    fn derived_credential_revocation_fails_closed_when_audit_sink_is_unavailable() {
        let sink = TestAuditSink {
            events: Mutex::new(Vec::new()),
            fail: true,
        };
        let mut revoked = false;
        let result = revoke_derived_credential(b"credential-reference-456", &sink, || {
            revoked = true;
            Ok::<_, ()>(())
        });
        assert_eq!(
            result,
            Err(CredentialRevocationError::AuditUnavailableBeforeRevocation)
        );
        assert!(!revoked);
    }
}
