//! Pluggable root-unseal port and the mandatory Shamir adapter.
//!
//! The default controller path always uses Shamir with an exact 2-of-3 policy.
//! Alternate providers are opt-in and must authenticate the expected ceremony
//! identifier before returning root material.

use std::fmt;

use async_trait::async_trait;
use aws_lc_rs::constant_time::verify_slices_are_equal;
use ferrum_recovery::{RecoveryPolicy, RecoveryShare, recover_secret};
use zeroize::Zeroizing;

/// Inputs accepted by an explicitly selected unseal provider.
pub enum UnsealSource<'a> {
    /// Offline recovery shares from the configured root ceremony.
    Shamir(&'a [RecoveryShare]),
    /// An opaque provider-wrapped root envelope. This path is never selected implicitly.
    Kms(&'a WrappedRootEnvelope),
}

/// Opaque ciphertext metadata for an explicitly selected provider.
///
/// This object is not a persistence format. Durable encoding and storage are
/// part of Phase 1.7. Debug output never includes ciphertext bytes.
pub struct WrappedRootEnvelope {
    key_id: String,
    key_version: u64,
    ciphertext: Vec<u8>,
}

impl WrappedRootEnvelope {
    pub fn new(
        key_id: impl Into<String>,
        key_version: u64,
        ciphertext: Vec<u8>,
    ) -> Result<Self, UnsealerError> {
        let key_id = key_id.into();
        if !valid_key_id(&key_id) || key_version == 0 || ciphertext.is_empty() {
            return Err(UnsealerError::InvalidWrappedRoot);
        }
        Ok(Self {
            key_id,
            key_version,
            ciphertext,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Provider-specific envelope version, not a key-material version.
    pub fn key_version(&self) -> u64 {
        self.key_version
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for WrappedRootEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WrappedRootEnvelope")
            .field("key_id", &self.key_id)
            .field("key_version", &self.key_version)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// Authenticated, non-secret context supplied to an unseal provider.
pub struct UnsealRequest<'a> {
    expected_ceremony_id: [u8; 16],
    source: UnsealSource<'a>,
}

impl<'a> UnsealRequest<'a> {
    pub fn from_source(expected_ceremony_id: [u8; 16], source: UnsealSource<'a>) -> Self {
        Self {
            expected_ceremony_id,
            source,
        }
    }

    pub fn from_shamir(expected_ceremony_id: [u8; 16], shares: &'a [RecoveryShare]) -> Self {
        Self::from_source(expected_ceremony_id, UnsealSource::Shamir(shares))
    }

    pub fn from_wrapped(expected_ceremony_id: [u8; 16], wrapped_root: &'a WrappedRootEnvelope) -> Self {
        Self::from_source(expected_ceremony_id, UnsealSource::Wrapped(wrapped_root))
    }

    pub fn expected_ceremony_id(&self) -> [u8; 16] {
        self.expected_ceremony_id
    }

    pub fn source(&self) -> &UnsealSource<'a> {
        &self.source
    }
}

/// Non-sensitive provider errors. Callers should expose only a generic unseal
/// rejection and must not log ciphertext, plaintext or credential details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsealerError {
    InvalidSource,
    InvalidConfiguration,
    InvalidWrappedRoot,
    QuorumRejected,
    CeremonyMismatch,
    AuthenticationFailed,
    AccessDenied,
    ProviderUnavailable,
    ProviderTimeout,
    ProviderFailure,
}

impl fmt::Display for UnsealerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSource => "unseal source is not supported by this provider",
            Self::InvalidConfiguration => "unsealer configuration is invalid",
            Self::InvalidWrappedRoot => "wrapped root metadata is invalid",
            Self::QuorumRejected => "Shamir unseal quorum rejected",
            Self::CeremonyMismatch => "unseal ceremony does not match configured root",
            Self::AuthenticationFailed => "unseal provider authentication failed",
            Self::AccessDenied => "unseal provider access denied",
            Self::ProviderUnavailable => "unseal provider unavailable",
            Self::ProviderTimeout => "unseal provider timed out",
            Self::ProviderFailure => "unseal provider operation failed",
        })
    }
}

impl std::error::Error for UnsealerError {}

/// Asynchronous, object-safe unseal extension point.
///
/// Implementations must authenticate the expected ceremony identifier and
/// return only complete, authenticated root material in zeroizing memory.
/// Cancellation must not commit a controller state transition. There is no
/// implicit provider fallback.
#[async_trait]
pub trait Unsealer: Send + Sync {
    async fn unseal(&self, request: UnsealRequest<'_>)
    -> Result<Zeroizing<Vec<u8>>, UnsealerError>;
}

/// Mandatory and default Community unseal adapter: Shamir 2-of-3.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShamirUnsealer;

impl ShamirUnsealer {
    /// Reconstructs only an exact 2-of-3 FRS1 ceremony matching the controller.
    ///
    /// One share, duplicate participants, corrupt shares, a different
    /// ceremony, a 5-of-3 recovery set, or any other policy is rejected.
    pub fn unseal_shares(
        expected_ceremony_id: [u8; 16],
        shares: &[RecoveryShare],
    ) -> Result<Zeroizing<Vec<u8>>, UnsealerError> {
        let required =
            RecoveryPolicy::new(2, 3).map_err(|_| UnsealerError::InvalidConfiguration)?;
        if !(2..=3).contains(&shares.len()) || shares.iter().any(|share| share.policy() != required)
        {
            return Err(UnsealerError::QuorumRejected);
        }

        let first = shares.first().ok_or(UnsealerError::QuorumRejected)?;
        let supplied_ceremony_id = first.ceremony_id();
        if verify_slices_are_equal(&expected_ceremony_id, &supplied_ceremony_id).is_err()
            || shares.iter().any(|share| {
                verify_slices_are_equal(&supplied_ceremony_id, &share.ceremony_id()).is_err()
            })
        {
            return Err(UnsealerError::CeremonyMismatch);
        }

        recover_secret(shares).map_err(|_| UnsealerError::QuorumRejected)
    }
}

#[async_trait]
impl Unsealer for ShamirUnsealer {
    async fn unseal(
        &self,
        request: UnsealRequest<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, UnsealerError> {
        match request.source() {
            UnsealSource::Shamir(shares) => {
                Self::unseal_shares(request.expected_ceremony_id(), shares)
            }
            UnsealSource::Wrapped(_) => Err(UnsealerError::InvalidSource),
        }
    }
}

fn valid_key_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 2048
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/+-".contains(byte))
}

#[cfg(test)]
mod tests {
    use super::{ShamirUnsealer, UnsealerError};
    use ferrum_recovery::{RecoveryPolicy, RecoveryShare, split_secret};

    fn shares(root: &[u8]) -> Vec<RecoveryShare> {
        split_secret(root, RecoveryPolicy::new(2, 3).unwrap()).unwrap()
    }

    fn copy_share(share: &RecoveryShare) -> RecoveryShare {
        RecoveryShare::decode(share.as_bytes()).unwrap()
    }

    #[test]
    fn two_distinct_shares_unseal_the_bound_ceremony() {
        let root = b"synthetic 2-of-3 unseal root";
        let shares = shares(root);
        let recovered = ShamirUnsealer::unseal_shares(shares[0].ceremony_id(), &shares[..2])
            .expect("two distinct shares must unseal");
        assert_eq!(recovered.as_slice(), root);
    }

    #[test]
    fn one_share_is_rejected() {
        let shares = shares(b"synthetic one-share rejection root");
        assert_eq!(
            ShamirUnsealer::unseal_shares(shares[0].ceremony_id(), &shares[..1]).err(),
            Some(UnsealerError::QuorumRejected)
        );
    }

    #[test]
    fn duplicate_participants_are_rejected() {
        let shares = shares(b"synthetic duplicate-share root");
        let duplicate = [copy_share(&shares[0]), copy_share(&shares[0])];
        assert_eq!(
            ShamirUnsealer::unseal_shares(shares[0].ceremony_id(), &duplicate).err(),
            Some(UnsealerError::QuorumRejected)
        );
    }

    #[test]
    fn other_ceremonies_and_corrupted_shares_are_rejected() {
        let first = shares(b"synthetic first ceremony root");
        let second = shares(b"synthetic second ceremony root");
        let mixed = [copy_share(&first[0]), copy_share(&second[1])];
        assert_eq!(
            ShamirUnsealer::unseal_shares(first[0].ceremony_id(), &mixed).err(),
            Some(UnsealerError::CeremonyMismatch)
        );

        let mut corrupted_bytes = first[0].as_bytes().to_vec();
        let last = corrupted_bytes.len() - 1;
        corrupted_bytes[last] ^= 0x80;
        let corrupted = RecoveryShare::decode(&corrupted_bytes).unwrap();
        let damaged = [corrupted, copy_share(&first[1])];
        assert_eq!(
            ShamirUnsealer::unseal_shares(first[0].ceremony_id(), &damaged).err(),
            Some(UnsealerError::QuorumRejected)
        );
    }

    #[test]
    fn generic_five_of_three_recovery_default_is_not_an_unseal_fallback() {
        let shares = split_secret(
            b"synthetic generic recovery root",
            RecoveryPolicy::default(),
        )
        .unwrap();
        assert_eq!(
            ShamirUnsealer::unseal_shares(shares[0].ceremony_id(), &shares[..3]).err(),
            Some(UnsealerError::QuorumRejected)
        );
    }

    #[test]
    fn invalid_expected_ceremony_is_rejected() {
        let shares = shares(b"synthetic expected ceremony root");
        assert_eq!(
            ShamirUnsealer::unseal_shares([0xA5; 16], &shares[..2]).err(),
            Some(UnsealerError::CeremonyMismatch)
        );
    }
}
