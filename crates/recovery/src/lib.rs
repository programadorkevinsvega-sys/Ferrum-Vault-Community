#![forbid(unsafe_code)]

//! Offline root recovery primitives for Ferrum Community.
//!
//! This crate has no storage, networking, logging, database, or service adapter.
//! A RecoveryShare is an explicit in-memory custody object. The caller is
//! responsible for transferring each share directly to its custodian and for
//! protecting any copy made outside this type.

use std::collections::HashSet;
use std::fmt;

use aws_lc_rs::hmac::{self, Key, HMAC_SHA256};
use rand::rngs::{StdRng, SysRng};
use rand_core::{CryptoRng, Rng, SeedableRng};
use vsss_rs::Gf256;
use zeroize::{Zeroize, Zeroizing};

const SHARE_MAGIC: &[u8; 4] = b"FRS1";
const SHARE_VERSION: u16 = 1;
const HEADER_WITHOUT_TAG_LEN: usize = 32;
const TAG_LEN: usize = 32;
const HEADER_LEN: usize = HEADER_WITHOUT_TAG_LEN + TAG_LEN;
const CHECK_KEY_LEN: usize = 32;
const MAC_DOMAIN: &[u8] = b"Ferrum Community recovery share FRS1 integrity v1\0";

/// Approved Shamir custody policy. The default is five shares with a threshold
/// of three. Both values can be configured; fewer than two shares or a 1-of-n
/// policy is rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryPolicy {
    threshold: u8,
    share_count: u8,
}

impl RecoveryPolicy {
    pub fn new(threshold: usize, share_count: usize) -> Result<Self, RecoveryError> {
        if threshold < 2 || share_count < threshold || share_count > 255 {
            return Err(RecoveryError::InvalidPolicy);
        }
        Ok(Self {
            threshold: u8::try_from(threshold).map_err(|_| RecoveryError::InvalidPolicy)?,
            share_count: u8::try_from(share_count).map_err(|_| RecoveryError::InvalidPolicy)?,
        })
    }

    pub const fn threshold(self) -> usize {
        self.threshold as usize
    }

    pub const fn share_count(self) -> usize {
        self.share_count as usize
    }
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self {
            threshold: 3,
            share_count: 5,
        }
    }
}

/// A single FRS1 recovery share. Debug output is redacted. There is deliberately
/// no Clone, Serialize, Display, or implicit persistence implementation.
pub struct RecoveryShare {
    encoded: Zeroizing<Vec<u8>>,
}

impl RecoveryShare {
    /// Strictly parses one complete FRS1 envelope and takes a zeroizing copy.
    pub fn decode(input: &[u8]) -> Result<Self, RecoveryError> {
        parse_share(input)?;
        Ok(Self {
            encoded: Zeroizing::new(input.to_vec()),
        })
    }

    /// Returns the canonical bytes for explicit custodian handoff.
    ///
    /// The returned slice remains secret material: do not log it, include it in
    /// fixtures, store it in the service, or send it through ordinary telemetry.
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Returns the public participant identifier encoded in the share.
    pub fn participant_id(&self) -> u8 {
        self.encoded[HEADER_LEN]
    }

    /// Returns the public policy attached to this share.
    pub fn policy(&self) -> RecoveryPolicy {
        RecoveryPolicy {
            threshold: self.encoded[6],
            share_count: self.encoded[7],
        }
    }
}

impl fmt::Debug for RecoveryShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryShare")
            .field("redacted", &true)
            .field("encoded_len", &self.encoded.len())
            .finish()
    }
}

/// Non-sensitive errors returned by offline recovery operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    InvalidPolicy,
    EmptySecret,
    SecretTooLarge,
    RandomnessUnavailable,
    SplitFailed,
    MalformedShare,
    UnsupportedVersion(u16),
    InsufficientShares,
    TooManyShares,
    DuplicateParticipant,
    MismatchedCeremony,
    AuthenticationFailed,
    ReconstructionFailed,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "invalid Shamir recovery policy",
            Self::EmptySecret => "recovery secret must not be empty",
            Self::SecretTooLarge => "recovery secret exceeds the supported envelope size",
            Self::RandomnessUnavailable => "operating-system randomness is unavailable",
            Self::SplitFailed => "secret sharing operation failed",
            Self::MalformedShare => "malformed recovery share",
            Self::UnsupportedVersion(_) => "unsupported recovery-share format version",
            Self::InsufficientShares => "insufficient recovery shares",
            Self::TooManyShares => "too many recovery shares for the encoded policy",
            Self::DuplicateParticipant => "duplicate recovery participant",
            Self::MismatchedCeremony => "recovery shares belong to different ceremonies or policies",
            Self::AuthenticationFailed => "recovery-share integrity verification failed",
            Self::ReconstructionFailed => "recovery shares could not be reconstructed",
        })
    }
}

impl std::error::Error for RecoveryError {}

/// Splits root material using a fresh CSPRNG seeded from the operating system.
///
/// This operation runs offline and returns shares only to the caller. It never
/// writes them to disk or to service storage.
pub fn split_secret(
    secret: &[u8],
    policy: RecoveryPolicy,
) -> Result<Vec<RecoveryShare>, RecoveryError> {
    let mut operating_system_rng = SysRng::default();
    let mut rng = StdRng::try_from_rng(&mut operating_system_rng)
        .map_err(|_| RecoveryError::RandomnessUnavailable)?;
    split_secret_with_rng(secret, policy, &mut rng)
}

/// Generates root material of the caller-selected length from an OS-seeded
/// CSPRNG and returns only its Shamir shares. No default root size is imposed:
/// the caller must use the size approved for the key hierarchy being created.
pub fn generate_secret_shares(
    secret_len: usize,
    policy: RecoveryPolicy,
) -> Result<Vec<RecoveryShare>, RecoveryError> {
    if secret_len == 0 {
        return Err(RecoveryError::EmptySecret);
    }
    u32::try_from(secret_len).map_err(|_| RecoveryError::SecretTooLarge)?;

    let mut operating_system_rng = SysRng::default();
    let mut rng = StdRng::try_from_rng(&mut operating_system_rng)
        .map_err(|_| RecoveryError::RandomnessUnavailable)?;
    let mut secret = Zeroizing::new(vec![0_u8; secret_len]);
    rng.fill_bytes(secret.as_mut_slice());
    split_secret_with_rng(&secret, policy, &mut rng)
}

/// Splits root material with a caller-supplied cryptographically secure RNG.
///
/// This form supports controlled offline ceremony tooling and deterministic
/// tests. Production callers must supply a properly seeded CSPRNG implementing
/// rand_core::CryptoRng. Never use a fixed or user-chosen seed for a ceremony.
pub fn split_secret_with_rng<R: CryptoRng>(
    secret: &[u8],
    policy: RecoveryPolicy,
    rng: &mut R,
) -> Result<Vec<RecoveryShare>, RecoveryError> {
    if secret.is_empty() {
        return Err(RecoveryError::EmptySecret);
    }

    let secret_len = u32::try_from(secret.len()).map_err(|_| RecoveryError::SecretTooLarge)?;
    let payload_len = secret_len
        .checked_add(CHECK_KEY_LEN as u32)
        .ok_or(RecoveryError::SecretTooLarge)?;

    let mut ceremony_id = [0_u8; 16];
    rng.fill_bytes(&mut ceremony_id);

    // The verification key is shared together with the root secret. It is never
    // stored in a service or emitted separately from the recovery process.
    let mut check_key = Zeroizing::new([0_u8; CHECK_KEY_LEN]);
    rng.fill_bytes(&mut *check_key);

    let payload_capacity =
        usize::try_from(payload_len).map_err(|_| RecoveryError::SecretTooLarge)?;
    let mut protected_secret = Zeroizing::new(Vec::with_capacity(payload_capacity));
    protected_secret.extend_from_slice(secret);
    protected_secret.extend_from_slice(&*check_key);

    let mut header = Zeroizing::new(Vec::with_capacity(HEADER_WITHOUT_TAG_LEN));
    header.extend_from_slice(SHARE_MAGIC);
    header.extend_from_slice(&SHARE_VERSION.to_be_bytes());
    header.push(policy.threshold);
    header.push(policy.share_count);
    header.extend_from_slice(&ceremony_id);
    header.extend_from_slice(&secret_len.to_be_bytes());
    header.extend_from_slice(&payload_len.to_be_bytes());

    let tag = calculate_tag(&header[..], secret, &check_key[..]);
    let mut shares = Zeroizing::new(
        Gf256::split_bytes(
            policy.threshold(),
            policy.share_count(),
            &*protected_secret,
            rng,
        )
        .map_err(|_| RecoveryError::SplitFailed)?,
    );

    let mut encoded_shares = Vec::with_capacity(shares.len());
    for raw_share in shares.iter_mut() {
        let mut encoded = Zeroizing::new(Vec::with_capacity(HEADER_LEN + raw_share.len()));
        encoded.extend_from_slice(&header[..]);
        encoded.extend_from_slice(&tag);
        encoded.extend_from_slice(&raw_share[..]);
        raw_share.zeroize();
        encoded_shares.push(RecoveryShare { encoded });
    }

    ceremony_id.zeroize();
    Ok(encoded_shares)
}

/// Reconstructs root material from a threshold set of shares.
///
/// All supplied shares must be structurally valid, share one ceremony and
/// policy, and have distinct participant identifiers. The reconstructed
/// payload is authenticated before any root bytes are returned.
pub fn recover_secret(shares: &[RecoveryShare]) -> Result<Zeroizing<Vec<u8>>, RecoveryError> {
    let first = shares.first().ok_or(RecoveryError::InsufficientShares)?;
    let first_parts = parse_share(&first.encoded)?;
    let threshold = usize::from(first_parts.header[6]);
    let share_count = usize::from(first_parts.header[7]);

    if shares.len() < threshold {
        return Err(RecoveryError::InsufficientShares);
    }
    if shares.len() > share_count {
        return Err(RecoveryError::TooManyShares);
    }

    let mut participant_ids = HashSet::with_capacity(shares.len());
    let mut raw_shares = Zeroizing::new(Vec::with_capacity(shares.len()));

    for share in shares {
        let parts = parse_share(&share.encoded)?;
        if parts.header != first_parts.header || parts.tag != first_parts.tag {
            return Err(RecoveryError::MismatchedCeremony);
        }
        if !participant_ids.insert(parts.participant_id) {
            return Err(RecoveryError::DuplicateParticipant);
        }
        raw_shares.push(parts.raw_share.to_vec());
    }

    let combined = Gf256::combine_bytes(&raw_shares)
        .map_err(|_| RecoveryError::ReconstructionFailed)?;
    let combined = Zeroizing::new(combined);

    let secret_len = usize::try_from(first_parts.secret_len)
        .map_err(|_| RecoveryError::MalformedShare)?;
    let expected_payload_len = usize::try_from(first_parts.payload_len)
        .map_err(|_| RecoveryError::MalformedShare)?;
    if combined.len() != expected_payload_len || combined.len() != secret_len + CHECK_KEY_LEN {
        return Err(RecoveryError::ReconstructionFailed);
    }

    let (root_secret, check_key) = combined.split_at(secret_len);
    let key = Key::new(HMAC_SHA256, check_key);
    let mut authenticated = Zeroizing::new(
        Vec::with_capacity(MAC_DOMAIN.len() + first_parts.header.len() + root_secret.len()),
    );
    authenticated.extend_from_slice(MAC_DOMAIN);
    authenticated.extend_from_slice(first_parts.header);
    authenticated.extend_from_slice(root_secret);

    hmac::verify(&key, &authenticated[..], first_parts.tag)
        .map_err(|_| RecoveryError::AuthenticationFailed)?;

    Ok(Zeroizing::new(root_secret.to_vec()))
}

fn calculate_tag(
    header: &[u8],
    root_secret: &[u8],
    check_key: &[u8],
) -> [u8; TAG_LEN] {
    let key = Key::new(HMAC_SHA256, check_key);
    let mut authenticated = Zeroizing::new(Vec::with_capacity(
        MAC_DOMAIN.len() + header.len() + root_secret.len(),
    ));
    authenticated.extend_from_slice(MAC_DOMAIN);
    authenticated.extend_from_slice(header);
    authenticated.extend_from_slice(root_secret);
    let tag = hmac::sign(&key, &authenticated);
    let mut output = [0_u8; TAG_LEN];
    output.copy_from_slice(tag.as_ref());
    output
}

struct ShareParts<'a> {
    header: &'a [u8],
    tag: &'a [u8],
    secret_len: u32,
    payload_len: u32,
    participant_id: u8,
    raw_share: &'a [u8],
}

fn parse_share(input: &[u8]) -> Result<ShareParts<'_>, RecoveryError> {
    if input.len() < HEADER_LEN + 1 || input.get(..4) != Some(SHARE_MAGIC.as_slice()) {
        return Err(RecoveryError::MalformedShare);
    }

    let version = u16::from_be_bytes([input[4], input[5]]);
    if version != SHARE_VERSION {
        return Err(RecoveryError::UnsupportedVersion(version));
    }

    let threshold = input[6];
    let share_count = input[7];
    if threshold < 2 || share_count < threshold {
        return Err(RecoveryError::MalformedShare);
    }

    let secret_len = u32::from_be_bytes([input[24], input[25], input[26], input[27]]);
    let payload_len = u32::from_be_bytes([input[28], input[29], input[30], input[31]]);
    if secret_len == 0 || secret_len.checked_add(CHECK_KEY_LEN as u32) != Some(payload_len) {
        return Err(RecoveryError::MalformedShare);
    }

    let raw_share = &input[HEADER_LEN..];
    let expected_raw_len = usize::try_from(payload_len)
        .ok()
        .and_then(|length| length.checked_add(1))
        .ok_or(RecoveryError::MalformedShare)?;
    if raw_share.len() != expected_raw_len || raw_share[0] == 0 || raw_share[0] > share_count {
        return Err(RecoveryError::MalformedShare);
    }

    Ok(ShareParts {
        header: &input[..HEADER_WITHOUT_TAG_LEN],
        tag: &input[HEADER_WITHOUT_TAG_LEN..HEADER_LEN],
        secret_len,
        payload_len,
        participant_id: raw_share[0],
        raw_share,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        generate_secret_shares, recover_secret, split_secret, split_secret_with_rng,
        RecoveryError, RecoveryPolicy, RecoveryShare,
    };
    use rand::rngs::StdRng;
    use rand_core::SeedableRng;

    fn deterministic_split(secret: &[u8], policy: RecoveryPolicy, seed: u8) -> Vec<RecoveryShare> {
        let mut rng = StdRng::from_seed([seed; 32]);
        split_secret_with_rng(secret, policy, &mut rng).unwrap()
    }

    fn copy_share(share: &RecoveryShare) -> RecoveryShare {
        RecoveryShare::decode(share.as_bytes()).unwrap()
    }

    fn synthetic_secret(length: usize, domain: u8) -> Vec<u8> {
        (0..length)
            .map(|index| (index as u8).wrapping_mul(29).wrapping_add(domain))
            .collect()
    }

    #[test]
    fn default_policy_is_five_shares_and_threshold_three() {
        let policy = RecoveryPolicy::default();
        assert_eq!(policy.share_count(), 5);
        assert_eq!(policy.threshold(), 3);
    }

    #[test]
    fn policy_rejects_unsafe_and_unrepresentable_boundaries() {
        for (threshold, count) in [(0, 5), (1, 5), (3, 2), (256, 256), (2, 256)] {
            assert_eq!(
                RecoveryPolicy::new(threshold, count),
                Err(RecoveryError::InvalidPolicy)
            );
        }
        assert!(RecoveryPolicy::new(2, 2).is_ok());
        assert!(RecoveryPolicy::new(5, 255).is_ok());
    }

    #[test]
    fn every_three_of_five_subset_reconstructs_the_same_secret() {
        let secret = synthetic_secret(48, 0x41);
        let shares = deterministic_split(&secret, RecoveryPolicy::default(), 0x41);
        let mut combinations = 0;
        for first in 0..5 {
            for second in first + 1..5 {
                for third in second + 1..5 {
                    let selected = [
                        copy_share(&shares[first]),
                        copy_share(&shares[second]),
                        copy_share(&shares[third]),
                    ];
                    let recovered = recover_secret(&selected).unwrap();
                    assert_eq!(&*recovered, secret);
                    combinations += 1;
                }
            }
        }
        assert_eq!(combinations, 10);
    }

    #[test]
    fn deterministic_property_sweep_covers_lengths_and_thresholds() {
        for length in 1..=128 {
            let secret: Vec<u8> = (0..length)
                .map(|index| (index as u8).wrapping_mul(37).wrapping_add(length as u8))
                .collect();

            for (threshold, count) in [(2, 2), (2, 5), (3, 5), (4, 7), (5, 9)] {
                let policy = RecoveryPolicy::new(threshold, count).unwrap();
                let shares = deterministic_split(&secret, policy, length as u8);
                let selected: Vec<_> = shares[..threshold].iter().map(copy_share).collect();
                let recovered = recover_secret(&selected).unwrap();
                assert_eq!(&*recovered, secret);
            }
        }
    }

    #[test]
    fn fewer_than_threshold_shares_are_rejected() {
        let shares = deterministic_split(&synthetic_secret(32, 0x42), RecoveryPolicy::default(), 0x42);
        let selected = [copy_share(&shares[0]), copy_share(&shares[1])];
        assert_eq!(
            recover_secret(&selected),
            Err(RecoveryError::InsufficientShares)
        );
    }

    #[test]
    fn duplicate_participant_ids_are_rejected() {
        let shares = deterministic_split(&synthetic_secret(32, 0x43), RecoveryPolicy::default(), 0x43);
        let selected = [copy_share(&shares[0]), copy_share(&shares[0]), copy_share(&shares[2])];
        assert_eq!(
            recover_secret(&selected),
            Err(RecoveryError::DuplicateParticipant)
        );
    }

    #[test]
    fn share_from_another_ceremony_is_rejected() {
        let first = deterministic_split(&synthetic_secret(32, 0x44), RecoveryPolicy::default(), 0x44);
        let second = deterministic_split(&synthetic_secret(32, 0x45), RecoveryPolicy::default(), 0x45);
        let selected = [
            copy_share(&first[0]),
            copy_share(&first[1]),
            copy_share(&second[2]),
        ];
        assert_eq!(
            recover_secret(&selected),
            Err(RecoveryError::MismatchedCeremony)
        );
    }

    #[test]
    fn mutated_share_data_fails_integrity_verification() {
        let shares = deterministic_split(&synthetic_secret(32, 0x46), RecoveryPolicy::default(), 0x46);
        let mut tampered_bytes = shares[0].as_bytes().to_vec();
        let last = tampered_bytes.len() - 1;
        tampered_bytes[last] ^= 0x01;
        let tampered = RecoveryShare::decode(&tampered_bytes).unwrap();
        let selected = [
            tampered,
            copy_share(&shares[1]),
            copy_share(&shares[2]),
            copy_share(&shares[3]),
            copy_share(&shares[4]),
        ];
        assert_eq!(
            recover_secret(&selected),
            Err(RecoveryError::AuthenticationFailed)
        );
    }

    #[test]
    fn frs1_parser_rejects_every_truncation_and_trailing_data() {
        let share = deterministic_split(&synthetic_secret(32, 0x47), RecoveryPolicy::default(), 0x47).remove(0);
        let encoded = share.as_bytes();
        for end in 0..encoded.len() {
            assert!(
                RecoveryShare::decode(&encoded[..end]).is_err(),
                "prefix ending at {end} unexpectedly decoded"
            );
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(
            RecoveryShare::decode(&trailing).err(),
            Some(RecoveryError::MalformedShare)
        );
    }

    #[test]
    fn parser_rejects_unknown_version_and_invalid_identifiers() {
        let share = deterministic_split(&synthetic_secret(32, 0x48), RecoveryPolicy::default(), 0x48).remove(0);
        let mut unknown = share.as_bytes().to_vec();
        unknown[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            RecoveryShare::decode(&unknown).err(),
            Some(RecoveryError::UnsupportedVersion(2))
        );
        let mut zero_id = share.as_bytes().to_vec();
        zero_id[HEADER_LEN_FOR_TEST] = 0;
        assert_eq!(
            RecoveryShare::decode(&zero_id).err(),
            Some(RecoveryError::MalformedShare)
        );
    }

    const HEADER_LEN_FOR_TEST: usize = 64;

    #[test]
    fn debug_output_never_contains_encoded_share_material() {
        let share = deterministic_split(&synthetic_secret(16, 0x49), RecoveryPolicy::default(), 0x49).remove(0);
        let debug = format!("{share:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("FRS1"));
    }

    #[test]
    fn operating_system_rng_entry_point_splits_successfully() {
        let secret = synthetic_secret(32, 0x4A);
        let shares = split_secret(&secret, RecoveryPolicy::default()).unwrap();
        let selected = [&shares[0], &shares[1], &shares[2]];
        let copies = [
            RecoveryShare::decode(selected[0].as_bytes()).unwrap(),
            RecoveryShare::decode(selected[1].as_bytes()).unwrap(),
            RecoveryShare::decode(selected[2].as_bytes()).unwrap(),
        ];
        assert_eq!(&*recover_secret(&copies).unwrap(), secret);
    }

    #[test]
    fn ceremony_generation_returns_only_recoverable_shares() {
        let shares = generate_secret_shares(32, RecoveryPolicy::default()).unwrap();
        assert_eq!(shares.len(), 5);
        let selected = [
            copy_share(&shares[0]),
            copy_share(&shares[2]),
            copy_share(&shares[4]),
        ];
        assert_eq!(recover_secret(&selected).unwrap().len(), 32);
    }

    #[test]
    fn ceremony_generation_rejects_zero_length() {
        assert_eq!(
            generate_secret_shares(0, RecoveryPolicy::default()).unwrap_err(),
            RecoveryError::EmptySecret
        );
    }
}
