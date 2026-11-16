//! Phase 1.6 storage barrier: canonical AAD, strict envelopes, key versions,
//! durable nonce-use reservations and resumable re-encryption orchestration.
//!
//! This module deliberately has no in-memory production ledger or default
//! rotation/reservation numbers. A caller must inject a durable ledger and
//! explicitly supply the owner-approved numeric policy before encryption can
//! occur. The redb implementation of these contracts belongs to Phase 1.7.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::{Arc, Mutex, RwLock};

use aws_lc_rs::digest::{SHA256, digest};
use zeroize::Zeroizing;

use crate::kmp::KeyId;
use crate::{Aes256GcmProvider, CryptoError, SealedPayload};

const BARRIER_FORMAT_VERSION: u16 = 1;
const ENVELOPE_MAGIC: &[u8; 4] = b"FBE1";
const COMMUNITY_TENANT_ID: &[u8] = b"root";
const GCM_TAG_LEN: usize = 16;
const GCM_NONCE_LEN: usize = 12;
const MAX_GCM_INVOCATIONS: u64 = 1_u64 << 32;

/// Errors from the storage barrier. Diagnostics never contain paths, keys,
/// plaintext, ciphertext, AAD or nonce values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierError {
    InvalidPath,
    InvalidConfiguration,
    InvalidKeyVersion,
    InvalidEnvelope,
    UnsupportedFormatVersion(u16),
    KeyNotFound,
    ActiveKeyCannotBeRetired,
    KeyStillReferenced,
    NonceLedgerUnavailable,
    NonceLedgerInvalidReservation,
    NonceBudgetExhausted,
    RotationRequired,
    ActiveKeyVersionChanged,
    FutureKeyVersion,
    InvalidRotationJobId,
    InvalidRotationPage,
    LockPoisoned,
    Provider(CryptoError),
    NonceLedger(NonceLedgerError),
    KeyInventory(KeyInventoryError),
    RotationStore(RotationStoreError),
}

impl fmt::Display for BarrierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPath => "invalid canonical storage path",
            Self::InvalidConfiguration => "invalid barrier configuration",
            Self::InvalidKeyVersion => "invalid barrier key version",
            Self::InvalidEnvelope => "invalid barrier envelope",
            Self::UnsupportedFormatVersion(version) => {
                return write!(formatter, "unsupported barrier format version {version}");
            }
            Self::KeyNotFound => "barrier key version not found",
            Self::ActiveKeyCannotBeRetired => "active barrier key cannot be retired",
            Self::KeyStillReferenced => "barrier key still has retained dependencies",
            Self::NonceLedgerUnavailable => "durable nonce ledger unavailable",
            Self::NonceLedgerInvalidReservation => {
                "durable nonce ledger returned an invalid reservation"
            }
            Self::NonceBudgetExhausted => "barrier nonce-use budget exhausted",
            Self::RotationRequired => "barrier key rotation required before another encryption",
            Self::ActiveKeyVersionChanged => "active key version changed during re-encryption",
            Self::FutureKeyVersion => "stored envelope uses a future key version",
            Self::InvalidRotationJobId => "invalid re-encryption job identifier",
            Self::InvalidRotationPage => "invalid re-encryption page or cursor",
            Self::LockPoisoned => "barrier synchronization state unavailable",
            Self::Provider(error) => return write!(formatter, "{error}"),
            Self::NonceLedger(error) => return write!(formatter, "{error}"),
            Self::KeyInventory(error) => return write!(formatter, "{error}"),
            Self::RotationStore(error) => return write!(formatter, "{error}"),
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BarrierError {}

impl From<CryptoError> for BarrierError {
    fn from(value: CryptoError) -> Self {
        Self::Provider(value)
    }
}

impl From<NonceLedgerError> for BarrierError {
    fn from(value: NonceLedgerError) -> Self {
        Self::NonceLedger(value)
    }
}

impl From<KeyInventoryError> for BarrierError {
    fn from(value: KeyInventoryError) -> Self {
        Self::KeyInventory(value)
    }
}

impl From<RotationStoreError> for BarrierError {
    fn from(value: RotationStoreError) -> Self {
        Self::RotationStore(value)
    }
}

/// A path already canonicalized by the storage/API boundary.
///
/// This type authenticates the exact bytes supplied; it does not normalize,
/// decode, case-fold or infer a path from a tenant prefix.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CanonicalPath(Vec<u8>);

impl CanonicalPath {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, BarrierError> {
        let bytes = bytes.into();
        if bytes.is_empty() || u32::try_from(bytes.len()).is_err() {
            return Err(BarrierError::InvalidPath);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CanonicalPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalPath")
            .field("byte_len", &self.0.len())
            .finish()
    }
}

/// Exact ADR-0004 AAD encoding for format version 1.
///
/// Each field is encoded as u32-BE length followed by its bytes, in this
/// order: tenant_id ("root"), format_version (u16-BE), key_version (u64-BE),
/// canonical_path. Version widths follow the explicit Rust field types and
/// are covered by the golden compatibility vector below.
#[derive(Clone, Eq, PartialEq)]
pub struct BarrierAad(Vec<u8>);

impl BarrierAad {
    pub fn new(path: &CanonicalPath, key_version: u64) -> Result<Self, BarrierError> {
        if key_version == 0 {
            return Err(BarrierError::InvalidKeyVersion);
        }

        let format_version = BARRIER_FORMAT_VERSION.to_be_bytes();
        let key_version = key_version.to_be_bytes();
        let mut encoded = Vec::with_capacity(
            4 + COMMUNITY_TENANT_ID.len()
                + 4
                + format_version.len()
                + 4
                + key_version.len()
                + 4
                + path.as_bytes().len(),
        );
        append_length_prefixed(&mut encoded, COMMUNITY_TENANT_ID)?;
        append_length_prefixed(&mut encoded, &format_version)?;
        append_length_prefixed(&mut encoded, &key_version)?;
        append_length_prefixed(&mut encoded, path.as_bytes())?;
        Ok(Self(encoded))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for BarrierAad {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BarrierAad")
            .field("encoded_len", &self.0.len())
            .finish()
    }
}

fn append_length_prefixed(output: &mut Vec<u8>, field: &[u8]) -> Result<(), BarrierError> {
    let length = u32::try_from(field.len()).map_err(|_| BarrierError::InvalidConfiguration)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(field);
    Ok(())
}

/// Canonical FBE1 envelope containing the selected key id/version, random
/// 96-bit nonce and ciphertext with the full 128-bit GCM tag appended.
///
/// Wire format: magic[4], format_version[u16-BE], key_id_len[u16-BE], key_id,
/// key_version[u64-BE], nonce[12], ciphertext_and_tag_len[u32-BE],
/// ciphertext_and_tag. Trailing bytes are always rejected.
#[derive(Clone, Eq, PartialEq)]
pub struct BarrierEnvelope {
    format_version: u16,
    key_id: KeyId,
    key_version: u64,
    payload: SealedPayload,
}

impl BarrierEnvelope {
    pub fn new(
        key_id: KeyId,
        key_version: u64,
        payload: SealedPayload,
    ) -> Result<Self, BarrierError> {
        if key_version == 0
            || payload.ciphertext_and_tag.len() < GCM_TAG_LEN
            || u32::try_from(payload.ciphertext_and_tag.len()).is_err()
        {
            return Err(BarrierError::InvalidEnvelope);
        }
        Ok(Self {
            format_version: BARRIER_FORMAT_VERSION,
            key_id,
            key_version,
            payload,
        })
    }

    pub fn format_version(&self) -> u16 {
        self.format_version
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn key_version(&self) -> u64 {
        self.key_version
    }

    pub fn encode(&self) -> Vec<u8> {
        let key_id = self.key_id.as_str().as_bytes();
        let ciphertext = &self.payload.ciphertext_and_tag;
        let mut encoded =
            Vec::with_capacity(4 + 2 + 2 + key_id.len() + 8 + GCM_NONCE_LEN + 4 + ciphertext.len());
        encoded.extend_from_slice(ENVELOPE_MAGIC);
        encoded.extend_from_slice(&self.format_version.to_be_bytes());
        encoded.extend_from_slice(&(key_id.len() as u16).to_be_bytes());
        encoded.extend_from_slice(key_id);
        encoded.extend_from_slice(&self.key_version.to_be_bytes());
        encoded.extend_from_slice(&self.payload.nonce);
        encoded.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        encoded.extend_from_slice(ciphertext);
        encoded
    }

    pub fn decode(input: &[u8]) -> Result<Self, BarrierError> {
        let mut reader = EnvelopeReader::new(input);
        if reader.take(4)? != ENVELOPE_MAGIC {
            return Err(BarrierError::InvalidEnvelope);
        }
        let format_version = reader.read_u16()?;
        if format_version != BARRIER_FORMAT_VERSION {
            return Err(BarrierError::UnsupportedFormatVersion(format_version));
        }

        let key_id_len = reader.read_u16()?;
        if key_id_len == 0 {
            return Err(BarrierError::InvalidEnvelope);
        }
        let key_id_bytes = reader.take(usize::from(key_id_len))?;
        if !key_id_bytes.is_ascii() {
            return Err(BarrierError::InvalidEnvelope);
        }
        let key_id = KeyId::new(
            std::str::from_utf8(key_id_bytes).map_err(|_| BarrierError::InvalidEnvelope)?,
        )
        .map_err(|_| BarrierError::InvalidEnvelope)?;

        let key_version = reader.read_u64()?;
        if key_version == 0 {
            return Err(BarrierError::InvalidEnvelope);
        }

        let mut nonce = [0_u8; GCM_NONCE_LEN];
        nonce.copy_from_slice(reader.take(GCM_NONCE_LEN)?);
        let ciphertext_len =
            usize::try_from(reader.read_u32()?).map_err(|_| BarrierError::InvalidEnvelope)?;
        if ciphertext_len < GCM_TAG_LEN {
            return Err(BarrierError::InvalidEnvelope);
        }
        let ciphertext_and_tag = reader.take(ciphertext_len)?.to_vec();
        if !reader.is_empty() {
            return Err(BarrierError::InvalidEnvelope);
        }

        Ok(Self {
            format_version,
            key_id,
            key_version,
            payload: SealedPayload {
                nonce,
                ciphertext_and_tag,
            },
        })
    }
}

impl fmt::Debug for BarrierEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BarrierEnvelope")
            .field("format_version", &self.format_version)
            .field("key_id", &self.key_id)
            .field("key_version", &self.key_version)
            .field("nonce", &"[REDACTED]")
            .field(
                "ciphertext_and_tag_len",
                &self.payload.ciphertext_and_tag.len(),
            )
            .finish()
    }
}

struct EnvelopeReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> EnvelopeReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BarrierError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BarrierError::InvalidEnvelope)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(BarrierError::InvalidEnvelope)?;
        self.offset = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, BarrierError> {
        let mut bytes = [0_u8; 2];
        bytes.copy_from_slice(self.take(2)?);
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, BarrierError> {
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, BarrierError> {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(bytes))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.input.len()
    }
}

/// Durable ledger failures. The concrete persistent adapter is part of Phase
/// 1.7; this contract has no in-memory production fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonceLedgerError {
    Unavailable,
    CorruptState,
    CounterExhausted,
}

impl fmt::Display for NonceLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "durable nonce ledger unavailable",
            Self::CorruptState => "durable nonce ledger state invalid",
            Self::CounterExhausted => "durable nonce ledger counter exhausted",
        })
    }
}

impl std::error::Error for NonceLedgerError {}

/// A half-open, monotonically allocated reservation [start, end_exclusive).
/// The ledger must durably commit the high-water mark before returning it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonceReservation {
    start: u64,
    end_exclusive: u64,
}

impl NonceReservation {
    pub fn new(start: u64, end_exclusive: u64) -> Result<Self, NonceLedgerError> {
        if start == 0 || end_exclusive <= start {
            return Err(NonceLedgerError::CorruptState);
        }
        Ok(Self {
            start,
            end_exclusive,
        })
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn end_exclusive(&self) -> u64 {
        self.end_exclusive
    }
}

/// Atomic storage contract for per-key-version nonce-use reservations.
///
/// Implementations must serialize concurrent callers and processes, persist
/// the policy and high-water mark for each key version, reject attempts to
/// change that policy, persist the new mark before returning, never overlap
/// ranges, and never roll a reservation back. A possibly used range is spent
/// permanently after failure or loss of proof of consumption.
pub trait NonceUsageLedger: Send + Sync {
    fn reserve(
        &self,
        key_id: &KeyId,
        key_version: u64,
        config: NonceBudgetConfig,
    ) -> Result<NonceReservation, NonceLedgerError>;
}

/// Explicit policy values; no Default implementation exists because ADR-0004
/// leaves the production rotation threshold and reservation block size
/// pending owner approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonceBudgetConfig {
    reservation_block_size: NonZeroU64,
    rotation_threshold: NonZeroU64,
}

impl NonceBudgetConfig {
    pub fn new(
        reservation_block_size: NonZeroU64,
        rotation_threshold: NonZeroU64,
    ) -> Result<Self, BarrierError> {
        if rotation_threshold.get() >= MAX_GCM_INVOCATIONS
            || reservation_block_size.get() > rotation_threshold.get()
        {
            return Err(BarrierError::InvalidConfiguration);
        }
        Ok(Self {
            reservation_block_size,
            rotation_threshold,
        })
    }

    pub fn reservation_block_size(&self) -> NonZeroU64 {
        self.reservation_block_size
    }

    pub fn rotation_threshold(&self) -> NonZeroU64 {
        self.rotation_threshold
    }
}

#[derive(Clone, Copy, Debug)]
struct ReservationCursor {
    next: u64,
    end_exclusive: u64,
}

/// Tracks locally cached durable reservations. On restart this cache is lost;
/// the next reservation begins at the persisted ledger high-water mark.
pub struct NonceBudget {
    config: NonceBudgetConfig,
    ledger: Arc<dyn NonceUsageLedger>,
    cursors: Mutex<HashMap<(KeyId, u64), ReservationCursor>>,
}

impl fmt::Debug for NonceBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NonceBudget")
            .field(
                "reservation_block_size",
                &self.config.reservation_block_size,
            )
            .field("rotation_threshold", &self.config.rotation_threshold)
            .finish()
    }
}

impl NonceBudget {
    pub fn new(config: NonceBudgetConfig, ledger: Arc<dyn NonceUsageLedger>) -> Self {
        Self {
            config,
            ledger,
            cursors: Mutex::new(HashMap::new()),
        }
    }

    fn consume(&self, key_id: &KeyId, key_version: u64) -> Result<u64, BarrierError> {
        if key_version == 0 {
            return Err(BarrierError::InvalidKeyVersion);
        }

        let mut cursors = self
            .cursors
            .lock()
            .map_err(|_| BarrierError::LockPoisoned)?;
        let map_key = (key_id.clone(), key_version);

        if let Some(cursor) = cursors.get_mut(&map_key)
            && cursor.next < cursor.end_exclusive
        {
            if cursor.next > self.config.rotation_threshold.get() {
                return Err(BarrierError::RotationRequired);
            }
            let ticket = cursor.next;
            cursor.next += 1;
            return Ok(ticket);
        }

        let reservation = self.ledger.reserve(key_id, key_version, self.config)?;
        let reserved_count = reservation
            .end_exclusive
            .checked_sub(reservation.start)
            .ok_or(BarrierError::NonceLedgerInvalidReservation)?;
        if reserved_count != self.config.reservation_block_size.get() {
            return Err(BarrierError::NonceLedgerInvalidReservation);
        }

        // If the next complete block would cross the configured threshold,
        // discard it and require rotation. Do not silently reserve a smaller,
        // implicit block size.
        if reservation.end_exclusive - 1 > self.config.rotation_threshold.get() {
            return Err(BarrierError::RotationRequired);
        }

        let ticket = reservation.start;
        cursors.insert(
            map_key,
            ReservationCursor {
                next: reservation.start + 1,
                end_exclusive: reservation.end_exclusive,
            },
        );
        Ok(ticket)
    }
}

/// One versioned data-encryption key. Key material is consumed into a
/// zeroizing temporary while AWS-LC constructs its provider handle.
pub struct VersionedDataKey {
    version: u64,
    provider: Arc<Aes256GcmProvider>,
}

impl VersionedDataKey {
    pub fn new(version: u64, key_bytes: [u8; 32]) -> Result<Self, BarrierError> {
        if version == 0 {
            return Err(BarrierError::InvalidKeyVersion);
        }
        let key_bytes = Zeroizing::new(key_bytes);
        let provider = Arc::new(Aes256GcmProvider::new(&key_bytes)?);
        Ok(Self { version, provider })
    }
}

/// Key-version registry for one logical key id. Reads can access retained
/// versions; writes always select the single active version.
pub struct BarrierKeyring {
    key_id: KeyId,
    state: RwLock<KeyringState>,
}

struct KeyringState {
    active_version: u64,
    keys: BTreeMap<u64, Arc<Aes256GcmProvider>>,
}

impl fmt::Debug for BarrierKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let active = self.active_version().ok();
        formatter
            .debug_struct("BarrierKeyring")
            .field("key_id", &self.key_id)
            .field("active_version", &active)
            .finish()
    }
}

impl BarrierKeyring {
    pub fn new(
        key_id: KeyId,
        active_version: u64,
        keys: Vec<VersionedDataKey>,
    ) -> Result<Self, BarrierError> {
        if active_version == 0 || keys.is_empty() {
            return Err(BarrierError::InvalidConfiguration);
        }
        let mut registered = BTreeMap::new();
        for key in keys {
            if registered.insert(key.version, key.provider).is_some() {
                return Err(BarrierError::InvalidConfiguration);
            }
        }
        let highest_version = registered.keys().next_back().copied();
        if !registered.contains_key(&active_version) || highest_version != Some(active_version) {
            return Err(BarrierError::InvalidConfiguration);
        }
        Ok(Self {
            key_id,
            state: RwLock::new(KeyringState {
                active_version,
                keys: registered,
            }),
        })
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn active_version(&self) -> Result<u64, BarrierError> {
        self.state
            .read()
            .map(|state| state.active_version)
            .map_err(|_| BarrierError::LockPoisoned)
    }

    fn provider_for(&self, version: u64) -> Result<Arc<Aes256GcmProvider>, BarrierError> {
        self.state
            .read()
            .map_err(|_| BarrierError::LockPoisoned)?
            .keys
            .get(&version)
            .cloned()
            .ok_or(BarrierError::KeyNotFound)
    }

    /// Adds a strictly newer DEK version and activates it for all subsequent
    /// writes. Existing versions remain readable until explicitly retired.
    pub fn install_and_activate(
        &self,
        version: u64,
        key_bytes: [u8; 32],
    ) -> Result<(), BarrierError> {
        let key = VersionedDataKey::new(version, key_bytes)?;
        let mut state = self.state.write().map_err(|_| BarrierError::LockPoisoned)?;
        let highest = state.keys.keys().next_back().copied().unwrap_or(0);
        if version <= highest || state.keys.contains_key(&version) {
            return Err(BarrierError::InvalidKeyVersion);
        }
        state.keys.insert(version, key.provider);
        state.active_version = version;
        Ok(())
    }

    /// Retires a non-active version only when the inventory can prove there
    /// are no live records, backups, snapshots or in-progress rotation jobs
    /// that still depend on it. Inventory errors fail closed.
    pub fn retire_key_version(
        &self,
        version: u64,
        inventory: &dyn KeyDependencyInventory,
    ) -> Result<(), BarrierError> {
        {
            let state = self.state.read().map_err(|_| BarrierError::LockPoisoned)?;
            if version == state.active_version {
                return Err(BarrierError::ActiveKeyCannotBeRetired);
            }
            if !state.keys.contains_key(&version) {
                return Err(BarrierError::KeyNotFound);
            }
        }

        if inventory.has_dependencies(&self.key_id, version)? {
            return Err(BarrierError::KeyStillReferenced);
        }

        let mut state = self.state.write().map_err(|_| BarrierError::LockPoisoned)?;
        if version == state.active_version {
            return Err(BarrierError::ActiveKeyCannotBeRetired);
        }
        state
            .keys
            .remove(&version)
            .ok_or(BarrierError::KeyNotFound)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyInventoryError {
    Unavailable,
    Incomplete,
}

impl fmt::Display for KeyInventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "key dependency inventory unavailable",
            Self::Incomplete => "key dependency inventory incomplete",
        })
    }
}

impl std::error::Error for KeyInventoryError {}

/// The implementation must inspect live ciphertext, backups, snapshots and
/// persisted rotation checkpoints, and must serialize the check against
/// restore/retention changes. A partial inventory is not proof of absence.
pub trait KeyDependencyInventory: Send + Sync {
    fn has_dependencies(&self, key_id: &KeyId, key_version: u64)
    -> Result<bool, KeyInventoryError>;
}

/// AES-256-GCM barrier for one key id and key-version registry.
pub struct BarrierCipher {
    keyring: Arc<BarrierKeyring>,
    nonce_budget: Arc<NonceBudget>,
}

impl fmt::Debug for BarrierCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BarrierCipher")
            .field("key_id", &self.keyring.key_id)
            .finish_non_exhaustive()
    }
}

impl BarrierCipher {
    pub fn new(keyring: Arc<BarrierKeyring>, nonce_budget: Arc<NonceBudget>) -> Self {
        Self {
            keyring,
            nonce_budget,
        }
    }

    pub fn keyring(&self) -> &Arc<BarrierKeyring> {
        &self.keyring
    }

    /// Encrypts with the active DEK. A durable nonce-use reservation is
    /// obtained before AWS-LC is allowed to create a random 96-bit nonce.
    pub fn seal(&self, path: &CanonicalPath, plaintext: &[u8]) -> Result<Vec<u8>, BarrierError> {
        self.seal_for_version(path, plaintext, None)
    }

    fn seal_for_version(
        &self,
        path: &CanonicalPath,
        plaintext: &[u8],
        required_version: Option<u64>,
    ) -> Result<Vec<u8>, BarrierError> {
        // Hold the keyring read lock through nonce reservation and encryption.
        // Activation takes the write lock, so an old-version write cannot
        // complete after the new version becomes active.
        let state = self
            .keyring
            .state
            .read()
            .map_err(|_| BarrierError::LockPoisoned)?;
        let key_version = state.active_version;
        if required_version.is_some_and(|required| required != key_version) {
            return Err(BarrierError::ActiveKeyVersionChanged);
        }
        let provider = state
            .keys
            .get(&key_version)
            .cloned()
            .ok_or(BarrierError::KeyNotFound)?;
        self.nonce_budget
            .consume(&self.keyring.key_id, key_version)?;
        let aad = BarrierAad::new(path, key_version)?;
        let payload = provider.seal(aad.as_bytes(), plaintext)?;
        BarrierEnvelope::new(self.keyring.key_id.clone(), key_version, payload)
            .map(|envelope| envelope.encode())
    }

    /// Parses the stored key version, reconstructs the exact AAD and releases
    /// plaintext only after AWS-LC authenticates the complete envelope.
    pub fn open(
        &self,
        path: &CanonicalPath,
        encoded_envelope: &[u8],
    ) -> Result<Vec<u8>, BarrierError> {
        let envelope = BarrierEnvelope::decode(encoded_envelope)?;
        if envelope.key_id != self.keyring.key_id {
            return Err(BarrierError::KeyNotFound);
        }
        let provider = self.keyring.provider_for(envelope.key_version)?;
        let aad = BarrierAad::new(path, envelope.key_version)?;
        provider
            .open(aad.as_bytes(), &envelope.payload)
            .map_err(BarrierError::Provider)
    }
}

/// Error returned by the durable rotation/checkpoint store contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationStoreError {
    Unavailable,
    CorruptState,
    InvalidCursor,
    TransactionFailed,
}

impl fmt::Display for RotationStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "durable rotation store unavailable",
            Self::CorruptState => "durable rotation state is corrupt",
            Self::InvalidCursor => "invalid durable rotation cursor",
            Self::TransactionFailed => "durable rotation transaction failed",
        })
    }
}

impl std::error::Error for RotationStoreError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationCheckpoint {
    target_key_version: u64,
    cursor: Option<Vec<u8>>,
    complete: bool,
}

impl RotationCheckpoint {
    pub fn new(
        target_key_version: u64,
        cursor: Option<Vec<u8>>,
        complete: bool,
    ) -> Result<Self, RotationStoreError> {
        if target_key_version == 0 || cursor.as_ref().is_some_and(Vec::is_empty) {
            return Err(RotationStoreError::CorruptState);
        }
        Ok(Self {
            target_key_version,
            cursor,
            complete,
        })
    }

    pub fn target_key_version(&self) -> u64 {
        self.target_key_version
    }

    pub fn cursor(&self) -> Option<&[u8]> {
        self.cursor.as_deref()
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

pub struct RotationRecord {
    path: CanonicalPath,
    envelope: Vec<u8>,
}

impl RotationRecord {
    pub fn new(path: CanonicalPath, envelope: Vec<u8>) -> Result<Self, RotationStoreError> {
        if envelope.is_empty() {
            return Err(RotationStoreError::CorruptState);
        }
        Ok(Self { path, envelope })
    }

    pub fn path(&self) -> &CanonicalPath {
        &self.path
    }

    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
}

impl fmt::Debug for RotationRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotationRecord")
            .field("path", &self.path)
            .field("envelope_len", &self.envelope.len())
            .finish()
    }
}

pub struct RotationPage {
    records: Vec<RotationRecord>,
    next_cursor: Option<Vec<u8>>,
    complete: bool,
}

impl RotationPage {
    pub fn new(
        records: Vec<RotationRecord>,
        next_cursor: Option<Vec<u8>>,
        complete: bool,
    ) -> Result<Self, RotationStoreError> {
        if next_cursor.as_ref().is_some_and(Vec::is_empty) {
            return Err(RotationStoreError::InvalidCursor);
        }
        Ok(Self {
            records,
            next_cursor,
            complete,
        })
    }

    pub fn records(&self) -> &[RotationRecord] {
        &self.records
    }

    pub fn next_cursor(&self) -> Option<&[u8]> {
        self.next_cursor.as_deref()
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

impl fmt::Debug for RotationPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RotationPage")
            .field("record_count", &self.records.len())
            .field("has_next_cursor", &self.next_cursor.is_some())
            .field("complete", &self.complete)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationAuditKind {
    Started,
    RecordReencrypted,
    RecordConflict,
    Checkpointed,
    Completed,
}

/// Structured audit metadata. Paths are represented only by a SHA-256
/// fingerprint; plaintext, envelopes, keys and nonces are never included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationAuditEvent {
    job_id: String,
    key_id: String,
    target_key_version: u64,
    source_key_version: Option<u64>,
    path_fingerprint: Option<[u8; 32]>,
    kind: RotationAuditKind,
}

impl RotationAuditEvent {
    pub fn new(
        job_id: &str,
        key_id: &KeyId,
        target_key_version: u64,
        source_key_version: Option<u64>,
        path_fingerprint: Option<[u8; 32]>,
        kind: RotationAuditKind,
    ) -> Result<Self, BarrierError> {
        validate_job_id(job_id)?;
        Ok(Self {
            job_id: job_id.to_owned(),
            key_id: key_id.as_str().to_owned(),
            target_key_version,
            source_key_version,
            path_fingerprint,
            kind,
        })
    }

    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn target_key_version(&self) -> u64 {
        self.target_key_version
    }

    pub fn source_key_version(&self) -> Option<u64> {
        self.source_key_version
    }

    pub fn path_fingerprint(&self) -> Option<&[u8; 32]> {
        self.path_fingerprint.as_ref()
    }

    pub fn kind(&self) -> RotationAuditKind {
        self.kind
    }
}

fn validate_job_id(job_id: &str) -> Result<(), BarrierError> {
    let bytes = job_id.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(byte))
    {
        return Err(BarrierError::InvalidRotationJobId);
    }
    Ok(())
}

/// Durable contract for resumable re-encryption.
///
/// Implementations must provide stable key-ordered pagination and durable
/// checkpoints. CAS and its corresponding success/conflict audit event must
/// commit atomically. Checkpoint advancement and its audit event must also
/// commit atomically. Replaying a page after a crash is safe: already migrated
/// rows carry the target version and are skipped.
pub trait RotationStore: Send + Sync {
    fn checkpoint(&self, job_id: &str) -> Result<Option<RotationCheckpoint>, RotationStoreError>;

    fn list_page(
        &self,
        after: Option<&[u8]>,
        limit: NonZeroUsize,
    ) -> Result<RotationPage, RotationStoreError>;

    fn compare_and_swap_with_audit(
        &self,
        path: &CanonicalPath,
        expected_envelope: &[u8],
        replacement_envelope: &[u8],
        success_event: RotationAuditEvent,
        conflict_event: RotationAuditEvent,
    ) -> Result<bool, RotationStoreError>;

    fn save_checkpoint_with_audit(
        &self,
        job_id: &str,
        checkpoint: RotationCheckpoint,
        event: RotationAuditEvent,
    ) -> Result<(), RotationStoreError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotationProgress {
    pub target_key_version: u64,
    pub scanned: usize,
    pub reencrypted: usize,
    pub conflicts: usize,
    pub complete: bool,
}

/// Bounded, restartable re-encryption worker. The caller schedules repeated
/// run_page invocations; the durable checkpoint is the source of truth.
pub struct RotationEngine {
    barrier: Arc<BarrierCipher>,
}

impl RotationEngine {
    pub fn new(barrier: Arc<BarrierCipher>) -> Self {
        Self { barrier }
    }

    pub fn run_page(
        &self,
        store: &dyn RotationStore,
        job_id: &str,
        limit: NonZeroUsize,
    ) -> Result<RotationProgress, BarrierError> {
        validate_job_id(job_id)?;
        let active_version = self.barrier.keyring.active_version()?;
        let checkpoint = match store.checkpoint(job_id)? {
            Some(checkpoint) => checkpoint,
            None => {
                let checkpoint = RotationCheckpoint::new(active_version, None, false)?;
                let event = RotationAuditEvent::new(
                    job_id,
                    self.barrier.keyring.key_id(),
                    active_version,
                    None,
                    None,
                    RotationAuditKind::Started,
                )?;
                store.save_checkpoint_with_audit(job_id, checkpoint.clone(), event)?;
                checkpoint
            }
        };

        if checkpoint.target_key_version != active_version {
            return Err(BarrierError::ActiveKeyVersionChanged);
        }
        if checkpoint.complete {
            return Ok(RotationProgress {
                target_key_version: active_version,
                scanned: 0,
                reencrypted: 0,
                conflicts: 0,
                complete: true,
            });
        }

        let page = store.list_page(checkpoint.cursor(), limit)?;
        if !page.complete {
            let next = page
                .next_cursor()
                .ok_or(BarrierError::InvalidRotationPage)?;
            if checkpoint.cursor() == Some(next) {
                return Err(BarrierError::InvalidRotationPage);
            }
        }

        let mut scanned = 0;
        let mut reencrypted = 0;
        let mut conflicts = 0;

        for record in page.records() {
            scanned += 1;
            let envelope = BarrierEnvelope::decode(record.envelope())?;
            if envelope.key_id != *self.barrier.keyring.key_id() {
                return Err(BarrierError::KeyNotFound);
            }
            if envelope.key_version > active_version {
                return Err(BarrierError::FutureKeyVersion);
            }
            // Authenticate every row, including those already on the target
            // version. A corrupt active-version envelope must not be counted
            // as successfully migrated merely because it needs no rewrite.
            let plaintext = Zeroizing::new(self.barrier.open(record.path(), record.envelope())?);
            if envelope.key_version == active_version {
                continue;
            }

            let replacement =
                self.barrier
                    .seal_for_version(record.path(), &plaintext, Some(active_version))?;
            let fingerprint = path_fingerprint(record.path());
            let success_event = RotationAuditEvent::new(
                job_id,
                self.barrier.keyring.key_id(),
                active_version,
                Some(envelope.key_version),
                Some(fingerprint),
                RotationAuditKind::RecordReencrypted,
            )?;
            let conflict_event = RotationAuditEvent::new(
                job_id,
                self.barrier.keyring.key_id(),
                active_version,
                Some(envelope.key_version),
                Some(fingerprint),
                RotationAuditKind::RecordConflict,
            )?;

            if store.compare_and_swap_with_audit(
                record.path(),
                record.envelope(),
                &replacement,
                success_event,
                conflict_event,
            )? {
                reencrypted += 1;
            } else {
                conflicts += 1;
            }
        }

        // A CAS conflict means a row may still require migration. Rewind
        // the checkpoint to the start of this page and retry it on the next
        // invocation; already migrated rows authenticate as active-version
        // rows and are safely skipped. Never report completion while a
        // conflict remains unresolved.
        let complete = page.complete && conflicts == 0;
        let next_cursor = if complete {
            None
        } else if conflicts > 0 {
            checkpoint.cursor().map(ToOwned::to_owned)
        } else {
            page.next_cursor().map(ToOwned::to_owned)
        };
        let next_checkpoint = RotationCheckpoint::new(active_version, next_cursor, complete)?;
        let event_kind = if complete {
            RotationAuditKind::Completed
        } else {
            RotationAuditKind::Checkpointed
        };
        let event = RotationAuditEvent::new(
            job_id,
            self.barrier.keyring.key_id(),
            active_version,
            None,
            None,
            event_kind,
        )?;
        store.save_checkpoint_with_audit(job_id, next_checkpoint, event)?;

        Ok(RotationProgress {
            target_key_version: active_version,
            scanned,
            reencrypted,
            conflicts,
            complete,
        })
    }
}

fn path_fingerprint(path: &CanonicalPath) -> [u8; 32] {
    let hash = digest(&SHA256, path.as_bytes());
    let mut output = [0_u8; 32];
    output.copy_from_slice(hash.as_ref());
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[derive(Default)]
    struct MemoryLedger {
        high_water: Mutex<HashMap<(String, u64), u64>>,
        fail: bool,
    }

    impl NonceUsageLedger for MemoryLedger {
        fn reserve(
            &self,
            key_id: &KeyId,
            key_version: u64,
            config: NonceBudgetConfig,
        ) -> Result<NonceReservation, NonceLedgerError> {
            if self.fail {
                return Err(NonceLedgerError::Unavailable);
            }
            let mut high_water = self
                .high_water
                .lock()
                .map_err(|_| NonceLedgerError::Unavailable)?;
            let next = high_water
                .entry((key_id.as_str().to_owned(), key_version))
                .or_insert(1);
            let end = next
                .checked_add(config.reservation_block_size().get())
                .ok_or(NonceLedgerError::CounterExhausted)?;
            let reservation = NonceReservation::new(*next, end)?;
            *next = end;
            Ok(reservation)
        }
    }

    struct MemoryInventory {
        has_dependencies: bool,
    }

    impl KeyDependencyInventory for MemoryInventory {
        fn has_dependencies(
            &self,
            _key_id: &KeyId,
            _key_version: u64,
        ) -> Result<bool, KeyInventoryError> {
            Ok(self.has_dependencies)
        }
    }

    #[derive(Default)]
    struct RotationState {
        records: BTreeMap<Vec<u8>, Vec<u8>>,
        checkpoints: HashMap<String, RotationCheckpoint>,
        audit: Vec<RotationAuditEvent>,
    }

    #[derive(Default)]
    struct MemoryRotationStore {
        state: Mutex<RotationState>,
        conflict_once: Mutex<Option<Vec<u8>>>,
    }

    impl MemoryRotationStore {
        fn insert(&self, path: CanonicalPath, envelope: Vec<u8>) {
            self.state
                .lock()
                .unwrap()
                .records
                .insert(path.as_bytes().to_vec(), envelope);
        }

        fn records(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
            self.state
                .lock()
                .unwrap()
                .records
                .iter()
                .map(|(path, envelope)| (path.clone(), envelope.clone()))
                .collect()
        }

        fn audit_count(&self) -> usize {
            self.state.lock().unwrap().audit.len()
        }

        fn cause_next_conflict(&self, concurrent_envelope: Vec<u8>) {
            *self.conflict_once.lock().unwrap() = Some(concurrent_envelope);
        }
    }

    impl RotationStore for MemoryRotationStore {
        fn checkpoint(
            &self,
            job_id: &str,
        ) -> Result<Option<RotationCheckpoint>, RotationStoreError> {
            Ok(self
                .state
                .lock()
                .map_err(|_| RotationStoreError::Unavailable)?
                .checkpoints
                .get(job_id)
                .cloned())
        }

        fn list_page(
            &self,
            after: Option<&[u8]>,
            limit: NonZeroUsize,
        ) -> Result<RotationPage, RotationStoreError> {
            let state = self
                .state
                .lock()
                .map_err(|_| RotationStoreError::Unavailable)?;
            let mut remaining = state
                .records
                .iter()
                .filter(|(path, _)| after.is_none_or(|cursor| path.as_slice() > cursor));
            let mut records = Vec::new();
            for _ in 0..limit.get() {
                let Some((path, envelope)) = remaining.next() else {
                    break;
                };
                records.push(RotationRecord::new(
                    CanonicalPath::new(path.clone())
                        .map_err(|_| RotationStoreError::CorruptState)?,
                    envelope.clone(),
                )?);
            }
            let has_more = remaining.next().is_some();
            let next_cursor = if has_more {
                records
                    .last()
                    .map(|record| record.path().as_bytes().to_vec())
            } else {
                None
            };
            RotationPage::new(records, next_cursor, !has_more)
        }

        fn compare_and_swap_with_audit(
            &self,
            path: &CanonicalPath,
            expected_envelope: &[u8],
            replacement_envelope: &[u8],
            success_event: RotationAuditEvent,
            conflict_event: RotationAuditEvent,
        ) -> Result<bool, RotationStoreError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| RotationStoreError::Unavailable)?;
            if let Some(concurrent_envelope) = self
                .conflict_once
                .lock()
                .map_err(|_| RotationStoreError::Unavailable)?
                .take()
            {
                state
                    .records
                    .insert(path.as_bytes().to_vec(), concurrent_envelope);
                state.audit.push(conflict_event);
                return Ok(false);
            }
            let Some(current) = state.records.get(path.as_bytes()) else {
                state.audit.push(conflict_event);
                return Ok(false);
            };
            if current.as_slice() != expected_envelope {
                state.audit.push(conflict_event);
                return Ok(false);
            }
            state
                .records
                .insert(path.as_bytes().to_vec(), replacement_envelope.to_vec());
            state.audit.push(success_event);
            Ok(true)
        }

        fn save_checkpoint_with_audit(
            &self,
            job_id: &str,
            checkpoint: RotationCheckpoint,
            event: RotationAuditEvent,
        ) -> Result<(), RotationStoreError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| RotationStoreError::Unavailable)?;
            state.checkpoints.insert(job_id.to_owned(), checkpoint);
            state.audit.push(event);
            Ok(())
        }
    }

    fn test_cipher() -> Arc<BarrierCipher> {
        let key_id = KeyId::new("community/barrier").unwrap();
        let key = VersionedDataKey::new(1, [0x31; 32]).unwrap();
        let keyring = Arc::new(BarrierKeyring::new(key_id, 1, vec![key]).unwrap());
        let ledger = Arc::new(MemoryLedger::default());
        let config =
            NonceBudgetConfig::new(NonZeroU64::new(4).unwrap(), NonZeroU64::new(12).unwrap())
                .unwrap();
        let budget = Arc::new(NonceBudget::new(config, ledger));
        Arc::new(BarrierCipher::new(keyring, budget))
    }

    #[test]
    fn aad_matches_adr_0004_golden_encoding() {
        let path = CanonicalPath::new(b"kv/apps/payments/secret".to_vec()).unwrap();
        let aad = BarrierAad::new(&path, 7).unwrap();
        let expected = b"\x00\x00\x00\x04root\
\x00\x00\x00\x02\x00\x01\
\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x07\
\x00\x00\x00\x17kv/apps/payments/secret";
        assert_eq!(aad.as_bytes(), expected);
    }

    #[test]
    fn aad_is_domain_bound_to_path_and_key_version() {
        let path = CanonicalPath::new(b"kv/a".to_vec()).unwrap();
        let other_path = CanonicalPath::new(b"kv/b".to_vec()).unwrap();
        assert_ne!(
            BarrierAad::new(&path, 1).unwrap(),
            BarrierAad::new(&other_path, 1).unwrap()
        );
        assert_ne!(
            BarrierAad::new(&path, 1).unwrap(),
            BarrierAad::new(&path, 2).unwrap()
        );
        assert_eq!(
            BarrierAad::new(&path, 0),
            Err(BarrierError::InvalidKeyVersion)
        );
    }

    #[test]
    fn barrier_envelope_round_trips_and_rejects_noncanonical_bytes() {
        let cipher = test_cipher();
        let path = CanonicalPath::new(b"kv/a".to_vec()).unwrap();
        let encoded = cipher.seal(&path, b"secret value").unwrap();
        let decoded = BarrierEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.key_version(), 1);
        assert_eq!(decoded.encode(), encoded);
        assert_eq!(cipher.open(&path, &encoded).unwrap(), b"secret value");

        for end in 0..encoded.len() {
            assert!(BarrierEnvelope::decode(&encoded[..end]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            BarrierEnvelope::decode(&trailing),
            Err(BarrierError::InvalidEnvelope)
        );
    }

    #[test]
    fn wrong_path_wrong_version_and_wrong_key_never_release_plaintext() {
        let cipher = test_cipher();
        let path = CanonicalPath::new(b"kv/accounts/one".to_vec()).unwrap();
        let wrong_path = CanonicalPath::new(b"kv/accounts/two".to_vec()).unwrap();
        let encoded = cipher.seal(&path, b"secret").unwrap();
        assert_eq!(
            cipher.open(&wrong_path, &encoded),
            Err(BarrierError::Provider(CryptoError::AuthenticationFailed))
        );

        let other_key_id = KeyId::new("community/other").unwrap();
        let other_keyring = Arc::new(
            BarrierKeyring::new(
                other_key_id,
                1,
                vec![VersionedDataKey::new(1, [0x55; 32]).unwrap()],
            )
            .unwrap(),
        );
        let other_ledger = Arc::new(MemoryLedger::default());
        let other_budget = Arc::new(NonceBudget::new(
            NonceBudgetConfig::new(NonZeroU64::new(4).unwrap(), NonZeroU64::new(12).unwrap())
                .unwrap(),
            other_ledger,
        ));
        let other = BarrierCipher::new(other_keyring, other_budget);
        assert_eq!(other.open(&path, &encoded), Err(BarrierError::KeyNotFound));
    }

    #[test]
    fn key_version_rotation_preserves_old_reads_and_uses_new_version_for_writes() {
        let cipher = test_cipher();
        let path = CanonicalPath::new(b"kv/rotation".to_vec()).unwrap();
        let old = cipher.seal(&path, b"before").unwrap();
        cipher
            .keyring()
            .install_and_activate(2, [0x44; 32])
            .unwrap();
        let new = cipher.seal(&path, b"after").unwrap();

        assert_eq!(BarrierEnvelope::decode(&old).unwrap().key_version(), 1);
        assert_eq!(BarrierEnvelope::decode(&new).unwrap().key_version(), 2);
        assert_eq!(cipher.open(&path, &old).unwrap(), b"before");
        assert_eq!(cipher.open(&path, &new).unwrap(), b"after");
        assert_eq!(
            cipher.keyring().install_and_activate(2, [0x66; 32]),
            Err(BarrierError::InvalidKeyVersion)
        );
    }

    #[test]
    fn nonce_reservations_are_disjoint_across_budget_instances() {
        let key_id = KeyId::new("community/barrier").unwrap();
        let ledger = Arc::new(MemoryLedger::default());
        let config =
            NonceBudgetConfig::new(NonZeroU64::new(2).unwrap(), NonZeroU64::new(6).unwrap())
                .unwrap();
        let first = NonceBudget::new(config, ledger.clone());
        let second = NonceBudget::new(config, ledger);

        assert_eq!(first.consume(&key_id, 1), Ok(1));
        assert_eq!(first.consume(&key_id, 1), Ok(2));
        assert_eq!(second.consume(&key_id, 1), Ok(3));
        assert_eq!(second.consume(&key_id, 1), Ok(4));
        assert_eq!(first.consume(&key_id, 1), Ok(5));
        assert_eq!(first.consume(&key_id, 1), Ok(6));
        assert_eq!(
            first.consume(&key_id, 1),
            Err(BarrierError::RotationRequired)
        );
    }

    #[test]
    fn concurrent_budget_instances_receive_disjoint_durable_ranges() {
        let ledger = Arc::new(MemoryLedger::default());
        let config =
            NonceBudgetConfig::new(NonZeroU64::new(2).unwrap(), NonZeroU64::new(128).unwrap())
                .unwrap();
        let key_id = KeyId::new("community/concurrent").unwrap();
        let mut workers = Vec::new();

        for _ in 0..16 {
            let ledger = ledger.clone();
            let key_id = key_id.clone();
            workers.push(std::thread::spawn(move || {
                let budget = NonceBudget::new(config, ledger);
                budget.consume(&key_id, 1).expect("reservation is unique")
            }));
        }

        let mut tickets = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker completes"))
            .collect::<Vec<_>>();
        tickets.sort_unstable();
        tickets.dedup();
        assert_eq!(tickets.len(), 16);
    }

    #[test]
    fn nonce_ledger_failure_fails_closed_before_encryption() {
        let key_id = KeyId::new("community/barrier").unwrap();
        let ledger = Arc::new(MemoryLedger {
            high_water: Mutex::new(HashMap::new()),
            fail: true,
        });
        let config =
            NonceBudgetConfig::new(NonZeroU64::new(1).unwrap(), NonZeroU64::new(8).unwrap())
                .unwrap();
        let budget = NonceBudget::new(config, ledger);
        assert_eq!(
            budget.consume(&key_id, 1),
            Err(BarrierError::NonceLedger(NonceLedgerError::Unavailable))
        );
    }

    #[test]
    fn nonce_policy_requires_explicit_values_below_the_gcm_invocation_ceiling() {
        assert!(
            NonceBudgetConfig::new(NonZeroU64::new(1).unwrap(), NonZeroU64::new(1).unwrap())
                .is_ok()
        );
        assert_eq!(
            NonceBudgetConfig::new(
                NonZeroU64::new(1).unwrap(),
                NonZeroU64::new(MAX_GCM_INVOCATIONS).unwrap()
            ),
            Err(BarrierError::InvalidConfiguration)
        );
        assert_eq!(
            NonceBudgetConfig::new(NonZeroU64::new(9).unwrap(), NonZeroU64::new(8).unwrap()),
            Err(BarrierError::InvalidConfiguration)
        );
    }

    #[test]
    fn old_key_cannot_be_retired_until_inventory_proves_no_dependencies() {
        let cipher = test_cipher();
        cipher
            .keyring()
            .install_and_activate(2, [0x77; 32])
            .unwrap();
        let key_id = cipher.keyring().key_id().clone();
        let dependent = MemoryInventory {
            has_dependencies: true,
        };
        assert_eq!(
            cipher.keyring().retire_key_version(1, &dependent),
            Err(BarrierError::KeyStillReferenced)
        );
        let clear = MemoryInventory {
            has_dependencies: false,
        };
        assert_eq!(cipher.keyring().retire_key_version(1, &clear), Ok(()));
        assert_eq!(
            cipher.keyring().retire_key_version(2, &clear),
            Err(BarrierError::ActiveKeyCannotBeRetired)
        );
        assert_ne!(key_id.as_str(), "");
    }

    #[test]
    fn re_encryption_is_checkpointed_resumable_and_audited() {
        let cipher = test_cipher();
        let first_path = CanonicalPath::new(b"kv/a".to_vec()).unwrap();
        let second_path = CanonicalPath::new(b"kv/b".to_vec()).unwrap();
        let first = cipher.seal(&first_path, b"alpha").unwrap();
        let second = cipher.seal(&second_path, b"beta").unwrap();
        let store = MemoryRotationStore::default();
        store.insert(first_path.clone(), first);
        store.insert(second_path.clone(), second);

        cipher
            .keyring()
            .install_and_activate(2, [0x88; 32])
            .unwrap();
        let engine = RotationEngine::new(cipher.clone());
        let first_page = engine
            .run_page(&store, "rotation-2026-01", NonZeroUsize::new(1).unwrap())
            .unwrap();
        assert_eq!(first_page.scanned, 1);
        assert_eq!(first_page.reencrypted, 1);
        assert!(!first_page.complete);

        // A new worker instance resumes from the durable checkpoint.
        let resumed = RotationEngine::new(cipher.clone());
        let second_page = resumed
            .run_page(&store, "rotation-2026-01", NonZeroUsize::new(1).unwrap())
            .unwrap();
        assert_eq!(second_page.scanned, 1);
        assert_eq!(second_page.reencrypted, 1);
        assert!(second_page.complete);

        for (path_bytes, envelope) in store.records() {
            let path = CanonicalPath::new(path_bytes).unwrap();
            assert_eq!(BarrierEnvelope::decode(&envelope).unwrap().key_version(), 2);
            let plaintext = cipher.open(&path, &envelope).unwrap();
            assert!(plaintext == b"alpha" || plaintext == b"beta");
        }
        assert!(store.audit_count() >= 5);
    }

    #[test]
    fn rotation_conflict_rewinds_page_and_resumes_until_all_rows_are_active() {
        let cipher = test_cipher();
        let path = CanonicalPath::new(b"kv/conflicting-write".to_vec()).unwrap();
        let initial = cipher.seal(&path, b"initial value").unwrap();

        cipher
            .keyring()
            .install_and_activate(2, [0x99; 32])
            .unwrap();
        let concurrent = cipher.seal(&path, b"concurrent writer value").unwrap();

        let store = MemoryRotationStore::default();
        store.insert(path.clone(), initial);
        store.cause_next_conflict(concurrent.clone());

        let engine = RotationEngine::new(cipher.clone());
        let first = engine
            .run_page(&store, "rotation-conflict", NonZeroUsize::new(1).unwrap())
            .unwrap();
        assert_eq!(first.conflicts, 1);
        assert!(!first.complete);

        let resumed = RotationEngine::new(cipher.clone());
        let second = resumed
            .run_page(&store, "rotation-conflict", NonZeroUsize::new(1).unwrap())
            .unwrap();
        assert_eq!(second.conflicts, 0);
        assert_eq!(second.reencrypted, 0);
        assert!(second.complete);

        let stored = store.records().pop().expect("record remains stored");
        let envelope = BarrierEnvelope::decode(&stored.1).unwrap();
        assert_eq!(envelope.key_version(), 2);
        assert_eq!(
            cipher.open(&path, &stored.1).unwrap(),
            b"concurrent writer value"
        );
        assert_eq!(stored.1, concurrent);
    }

    #[test]
    fn rotation_rejects_corrupt_envelopes_even_when_their_version_is_active() {
        let cipher = test_cipher();
        let path = CanonicalPath::new(b"kv/corrupt-active".to_vec()).unwrap();
        let mut encoded = cipher.seal(&path, b"synthetic data").unwrap();
        let last = encoded.last_mut().expect("GCM tag is present");
        *last ^= 0x01;

        let store = MemoryRotationStore::default();
        store.insert(path, encoded);
        let engine = RotationEngine::new(cipher);
        assert_eq!(
            engine.run_page(
                &store,
                "rotation-corrupt-active",
                NonZeroUsize::new(1).unwrap()
            ),
            Err(BarrierError::Provider(CryptoError::AuthenticationFailed))
        );
    }

    proptest! {
        #[test]
        fn aad_encoding_is_deterministic_and_path_injective(
            path in prop::collection::vec(any::<u8>(), 1..256),
            other in prop::collection::vec(any::<u8>(), 1..256),
            key_version in 1_u64..u64::MAX
        ) {
            prop_assume!(path != other);
            let first_path = CanonicalPath::new(path).unwrap();
            let second_path = CanonicalPath::new(other).unwrap();
            let first = BarrierAad::new(&first_path, key_version).unwrap();
            let repeated = BarrierAad::new(&first_path, key_version).unwrap();
            let other = BarrierAad::new(&second_path, key_version).unwrap();
            prop_assert_eq!(first.as_bytes(), repeated.as_bytes());
            prop_assert_ne!(first.as_bytes(), other.as_bytes());
        }

        #[test]
        fn envelope_parser_round_trips_generated_canonical_envelopes(
            nonce in any::<[u8; 12]>(),
            data in prop::collection::vec(any::<u8>(), 16..512),
            key_version in 1_u64..u64::MAX
        ) {
            let envelope = BarrierEnvelope::new(
                KeyId::new("community/property").unwrap(),
                key_version,
                SealedPayload { nonce, ciphertext_and_tag: data }
            ).unwrap();
            let encoded = envelope.encode();
            let decoded = BarrierEnvelope::decode(&encoded).unwrap();
            prop_assert_eq!(decoded.encode(), encoded);
            prop_assert_eq!(decoded, envelope);
        }
    }
}
