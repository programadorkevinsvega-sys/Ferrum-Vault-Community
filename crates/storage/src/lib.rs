#![forbid(unsafe_code)]

//! Durable Community storage contracts and redb implementation.
//! Protected plaintext must be encrypted before entering this crate.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use ferrum_crypto::barrier::{
    BarrierEnvelope, CanonicalPath, KeyDependencyInventory, KeyInventoryError, NonceBudgetConfig,
    NonceLedgerError, NonceReservation, NonceUsageLedger, RotationAuditEvent, RotationAuditKind,
    RotationCheckpoint, RotationPage, RotationRecord, RotationStore, RotationStoreError,
};
use ferrum_crypto::kmp::KeyId;
use redb::{
    Builder, ConcurrencyMode, Database, Durability, ReadableDatabase, ReadableTable,
    ReadableTableMetadata, TableDefinition, WriteTransaction,
};

const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("kv_v1");
const BARRIER: TableDefinition<&[u8], &[u8]> = TableDefinition::new("barrier_v1");
const NONCES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("nonce_ledger_v1");
const CHECKPOINTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rotation_checkpoints_v1");
const AUDIT: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rotation_audit_v1");
const DEPENDENCIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("key_dependencies_v1");
const RETIRED_KEYS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("retired_key_versions_v1");
const META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("storage_meta_v1");

const INVENTORY_COMPLETE: &[u8] = b"inventory-complete";
const INVENTORY_POLICY_VERSION: &[u8] = b"inventory-policy-version";
const KV_FBE1_SCAN_COMPLETE: &[u8] = b"kv-fbe1-scan-complete";
const BARRIER_ENVELOPE_MAGIC: &[u8; 4] = b"FBE1";
const AUDIT_SEQUENCE: &[u8] = b"audit-sequence";
const CURSOR_MAGIC: &[u8; 4] = b"FVC1";
const NONCE_MAGIC: &[u8; 4] = b"FNL1";
const CHECKPOINT_MAGIC: &[u8; 4] = b"FRC1";
const AUDIT_MAGIC: &[u8; 4] = b"FRA1";
const MAX_KEY_LEN: usize = 4096;
const MAX_VALUE_LEN: usize = 64 * 1024 * 1024;
const MAX_GCM_INVOCATIONS: u64 = 1_u64 << 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    Unavailable,
    CorruptRecord,
    InvalidInput,
    InvalidCursor,
    Conflict,
    LimitExceeded,
    VersionExhausted,
}
impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "durable storage unavailable",
            Self::CorruptRecord => "durable storage record is corrupt",
            Self::InvalidInput => "invalid storage input",
            Self::InvalidCursor => "invalid storage cursor",
            Self::Conflict => "storage precondition conflict",
            Self::LimitExceeded => "storage size or operation limit exceeded",
            Self::VersionExhausted => "storage record version exhausted",
        })
    }
}
impl std::error::Error for StorageError {}

#[derive(Clone, Eq, PartialEq)]
pub struct StoredValue {
    version: u64,
    value: Vec<u8>,
}
impl StoredValue {
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}
impl fmt::Debug for StoredValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredValue")
            .field("version", &self.version)
            .field("value_len", &self.value.len())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct KvRecord {
    key: Vec<u8>,
    version: u64,
    value: Vec<u8>,
}
impl KvRecord {
    pub fn key(&self) -> &[u8] {
        &self.key
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}
impl fmt::Debug for KvRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KvRecord")
            .field("key_len", &self.key.len())
            .field("version", &self.version)
            .field("value_len", &self.value.len())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordPage {
    records: Vec<KvRecord>,
    next_cursor: Option<Vec<u8>>,
}
impl RecordPage {
    pub fn records(&self) -> &[KvRecord] {
        &self.records
    }
    pub fn next_cursor(&self) -> Option<&[u8]> {
        self.next_cursor.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Precondition {
    key: Vec<u8>,
    expected_version: Option<u64>,
}
impl Precondition {
    /// None means the key must be absent; Some(v) means it must have version v.
    pub fn new(
        key: impl Into<Vec<u8>>,
        expected_version: Option<u64>,
    ) -> Result<Self, StorageError> {
        let key = key.into();
        validate_key(&key)?;
        if expected_version == Some(0) {
            return Err(StorageError::InvalidInput);
        }
        Ok(Self {
            key,
            expected_version,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mutation {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}
impl Mutation {
    pub fn put(key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Result<Self, StorageError> {
        let key = key.into();
        let value = value.into();
        validate_key(&key)?;
        validate_generic_value(&value)?;
        Ok(Self::Put { key, value })
    }
    pub fn delete(key: impl Into<Vec<u8>>) -> Result<Self, StorageError> {
        let key = key.into();
        validate_key(&key)?;
        Ok(Self::Delete { key })
    }
    fn key(&self) -> &[u8] {
        match self {
            Self::Put { key, .. } | Self::Delete { key } => key,
        }
    }
}

/// Shared backend-neutral CRUD/CAS contract.
pub trait KvBackend: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<StoredValue>, StorageError>;
    fn put(&self, key: &[u8], value: &[u8]) -> Result<u64, StorageError>;
    fn delete(&self, key: &[u8]) -> Result<bool, StorageError>;
    fn list(
        &self,
        prefix: &[u8],
        limit: usize,
        cursor: Option<&[u8]>,
    ) -> Result<RecordPage, StorageError>;
    fn compare_and_swap(
        &self,
        key: &[u8],
        expected_version: Option<u64>,
        replacement: Option<&[u8]>,
    ) -> Result<Option<u64>, StorageError>;
    fn apply_batch(
        &self,
        mutations: &[Mutation],
        preconditions: &[Precondition],
    ) -> Result<Vec<Option<u64>>, StorageError>;
}

#[derive(Clone)]
pub struct RedbStore {
    database: Arc<Database>,
}
impl fmt::Debug for RedbStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedbStore")
            .field("backend", &"redb/4.6.0")
            .field("concurrency", &"MultiWriter")
            .finish()
    }
}
impl RedbStore {
    /// Opens/creates a multi-process database. Concurrent writers serialize in redb.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let database = Builder::new()
            .set_concurrency_mode(ConcurrencyMode::MultiWriter)
            .create(path)
            .map_err(|_| StorageError::Unavailable)?;
        let store = Self {
            database: Arc::new(database),
        };
        store.initialize_inventory_state()?;
        Ok(store)
    }

    fn begin_write(&self) -> Result<WriteTransaction, StorageError> {
        let mut tx = self
            .database
            .begin_write()
            .map_err(|_| StorageError::Unavailable)?;
        tx.set_durability(Durability::Immediate)
            .map_err(|_| StorageError::Unavailable)?;
        Ok(tx)
    }

    fn initialize_inventory_state(&self) -> Result<(), StorageError> {
        let tx = self.begin_write()?;

        // Create the complete schema atomically. Empty databases must support
        // reads/deletes before a caller's first put creates any records.
        drop(tx.open_table(KV).map_err(|_| StorageError::Unavailable)?);
        drop(
            tx.open_table(BARRIER)
                .map_err(|_| StorageError::Unavailable)?,
        );
        drop(
            tx.open_table(NONCES)
                .map_err(|_| StorageError::Unavailable)?,
        );
        drop(
            tx.open_table(CHECKPOINTS)
                .map_err(|_| StorageError::Unavailable)?,
        );
        drop(
            tx.open_table(AUDIT)
                .map_err(|_| StorageError::Unavailable)?,
        );
        drop(
            tx.open_table(DEPENDENCIES)
                .map_err(|_| StorageError::Unavailable)?,
        );
        drop(
            tx.open_table(RETIRED_KEYS)
                .map_err(|_| StorageError::Unavailable)?,
        );

        let mut meta = tx.open_table(META).map_err(|_| StorageError::Unavailable)?;
        let inventory_policy_current = meta
            .get(INVENTORY_POLICY_VERSION)
            .map_err(|_| StorageError::Unavailable)?
            .map(|v| v.value().to_vec())
            .is_some_and(|version| version == [2]);
        if !inventory_policy_current {
            // Older versions inferred completeness from local table contents,
            // which cannot prove that external backups/snapshots were inventoried.
            // Require an explicit reconciliation under this policy.
            meta.insert(INVENTORY_COMPLETE, &[0_u8][..])
                .map_err(|_| StorageError::Unavailable)?;
            meta.insert(INVENTORY_POLICY_VERSION, &[2_u8][..])
                .map_err(|_| StorageError::Unavailable)?;
        }

        let scan_complete = meta
            .get(KV_FBE1_SCAN_COMPLETE)
            .map_err(|_| StorageError::Unavailable)?
            .map(|v| v.value().to_vec())
            .is_some_and(|value| value == [1]);
        // One-time migration scan for a prior version that may have persisted
        // FBE1 values through generic KV without updating key dependencies.
        if !scan_complete {
            let kv = tx.open_table(KV).map_err(|_| StorageError::Unavailable)?;
            let mut untracked_fbe1 = false;
            for entry in kv.iter().map_err(|_| StorageError::Unavailable)? {
                let (_, value) = entry.map_err(|_| StorageError::Unavailable)?;
                let (_, live) = decode_versioned_record(value.value())?;
                if live.as_deref().is_some_and(is_barrier_envelope) {
                    untracked_fbe1 = true;
                    break;
                }
            }
            drop(kv);
            meta.insert(KV_FBE1_SCAN_COMPLETE, &[1_u8][..])
                .map_err(|_| StorageError::Unavailable)?;
            if untracked_fbe1 {
                meta.insert(INVENTORY_COMPLETE, &[0_u8][..])
                    .map_err(|_| StorageError::Unavailable)?;
            }
        }
        drop(meta);
        tx.commit().map_err(|_| StorageError::Unavailable)
    }

    /// Stores a structurally valid FBE1 envelope and updates live-key dependencies atomically.
    pub fn put_encrypted(&self, path: &CanonicalPath, envelope: &[u8]) -> Result<(), StorageError> {
        validate_key(path.as_bytes())?;
        validate_value(envelope)?;
        let parsed = BarrierEnvelope::decode(envelope).map_err(|_| StorageError::CorruptRecord)?;
        let tx = self.begin_write()?;
        ensure_key_version_not_retired(&tx, parsed.key_id().as_str(), parsed.key_version())?;
        let records = tx
            .open_table(BARRIER)
            .map_err(|_| StorageError::Unavailable)?;
        let old = records
            .get(path.as_bytes())
            .map_err(|_| StorageError::Unavailable)?
            .map(|v| v.value().to_vec());
        drop(records);
        update_live_dependency(&tx, path.as_bytes(), old.as_deref(), Some(envelope))?;
        let mut records = tx
            .open_table(BARRIER)
            .map_err(|_| StorageError::Unavailable)?;
        records
            .insert(path.as_bytes(), envelope)
            .map_err(|_| StorageError::Unavailable)?;
        drop(records);
        tx.commit().map_err(|_| StorageError::Unavailable)
    }

    pub fn delete_encrypted(&self, path: &CanonicalPath) -> Result<bool, StorageError> {
        validate_key(path.as_bytes())?;
        let tx = self.begin_write()?;
        let records = tx
            .open_table(BARRIER)
            .map_err(|_| StorageError::Unavailable)?;
        let old = records
            .get(path.as_bytes())
            .map_err(|_| StorageError::Unavailable)?
            .map(|v| v.value().to_vec());
        drop(records);
        if old.is_none() {
            return Ok(false);
        }
        update_live_dependency(&tx, path.as_bytes(), old.as_deref(), None)?;
        let mut records = tx
            .open_table(BARRIER)
            .map_err(|_| StorageError::Unavailable)?;
        records
            .remove(path.as_bytes())
            .map_err(|_| StorageError::Unavailable)?;
        drop(records);
        tx.commit().map_err(|_| StorageError::Unavailable)?;
        Ok(true)
    }

    /// Register a dependency held by a backup, snapshot or active rotation job.
    pub fn register_dependency(
        &self,
        key_id: &str,
        key_version: u64,
        kind: DependencyKind,
        resource_id: &[u8],
    ) -> Result<(), StorageError> {
        let key = external_dependency_key(key_id, key_version, kind, resource_id)?;
        let tx = self.begin_write()?;
        ensure_key_version_not_retired(&tx, key_id, key_version)?;
        let mut table = tx
            .open_table(DEPENDENCIES)
            .map_err(|_| StorageError::Unavailable)?;
        table
            .insert(key.as_slice(), &[1_u8][..])
            .map_err(|_| StorageError::Unavailable)?;
        drop(table);
        tx.commit().map_err(|_| StorageError::Unavailable)
    }

    pub fn remove_dependency(
        &self,
        key_id: &str,
        key_version: u64,
        kind: DependencyKind,
        resource_id: &[u8],
    ) -> Result<bool, StorageError> {
        let key = external_dependency_key(key_id, key_version, kind, resource_id)?;
        let tx = self.begin_write()?;
        let mut table = tx
            .open_table(DEPENDENCIES)
            .map_err(|_| StorageError::Unavailable)?;
        let removed = table
            .remove(key.as_slice())
            .map_err(|_| StorageError::Unavailable)?
            .is_some();
        drop(table);
        tx.commit().map_err(|_| StorageError::Unavailable)?;
        Ok(removed)
    }

    /// Rebuild the live-record dependency index and mark it complete in one
    /// durable transaction. External backup/snapshot/job dependencies must
    /// already have been registered by the caller before this assertion.
    pub fn confirm_inventory_reconciled(&self) -> Result<(), StorageError> {
        let tx = self.begin_write()?;

        let kv = tx.open_table(KV).map_err(|_| StorageError::Unavailable)?;
        for entry in kv.iter().map_err(|_| StorageError::Unavailable)? {
            let (_, value) = entry.map_err(|_| StorageError::Unavailable)?;
            let (_, live) = decode_versioned_record(value.value())?;
            if live.as_deref().is_some_and(is_barrier_envelope) {
                return Err(StorageError::CorruptRecord);
            }
        }
        drop(kv);

        let mut live_dependencies = Vec::new();
        let retired = tx
            .open_table(RETIRED_KEYS)
            .map_err(|_| StorageError::Unavailable)?;
        let records = tx
            .open_table(BARRIER)
            .map_err(|_| StorageError::Unavailable)?;
        for entry in records.iter().map_err(|_| StorageError::Unavailable)? {
            let (path, envelope) = entry.map_err(|_| StorageError::Unavailable)?;
            let parsed = BarrierEnvelope::decode(envelope.value())
                .map_err(|_| StorageError::CorruptRecord)?;
            let retired_key = dependency_prefix(parsed.key_id().as_str(), parsed.key_version())?;
            if retired
                .get(retired_key.as_slice())
                .map_err(|_| StorageError::Unavailable)?
                .is_some()
            {
                return Err(StorageError::CorruptRecord);
            }
            live_dependencies.push(live_dependency_key(envelope.value(), path.value())?);
        }
        drop(records);
        drop(retired);

        let dependencies = tx
            .open_table(DEPENDENCIES)
            .map_err(|_| StorageError::Unavailable)?;
        let stale_live: Vec<Vec<u8>> = dependencies
            .iter()
            .map_err(|_| StorageError::Unavailable)?
            .filter_map(|entry| match entry {
                Ok((key, _)) if is_live_dependency(key.value()) => Some(Ok(key.value().to_vec())),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<_, _>>()
            .map_err(|_| StorageError::Unavailable)?;
        drop(dependencies);

        let mut dependencies = tx
            .open_table(DEPENDENCIES)
            .map_err(|_| StorageError::Unavailable)?;
        for key in stale_live {
            dependencies
                .remove(key.as_slice())
                .map_err(|_| StorageError::Unavailable)?;
        }
        for key in live_dependencies {
            dependencies
                .insert(key.as_slice(), &[1_u8][..])
                .map_err(|_| StorageError::Unavailable)?;
        }
        drop(dependencies);

        let mut meta = tx.open_table(META).map_err(|_| StorageError::Unavailable)?;
        meta.insert(INVENTORY_COMPLETE, &[1_u8][..])
            .map_err(|_| StorageError::Unavailable)?;
        drop(meta);
        tx.commit().map_err(|_| StorageError::Unavailable)
    }

    pub fn audit_count(&self) -> Result<u64, StorageError> {
        let tx = self
            .database
            .begin_read()
            .map_err(|_| StorageError::Unavailable)?;
        let table = tx
            .open_table(AUDIT)
            .map_err(|_| StorageError::Unavailable)?;
        table.len().map_err(|_| StorageError::Unavailable)
    }
}

impl KvBackend for RedbStore {
    fn get(&self, key: &[u8]) -> Result<Option<StoredValue>, StorageError> {
        validate_key(key)?;
        let tx = self
            .database
            .begin_read()
            .map_err(|_| StorageError::Unavailable)?;
        let table = tx.open_table(KV).map_err(|_| StorageError::Unavailable)?;
        let stored = table.get(key).map_err(|_| StorageError::Unavailable)?;
        match stored {
            Some(value) => {
                let (version, value) = decode_versioned_record(value.value())?;
                Ok(value.map(|value| StoredValue { version, value }))
            }
            None => Ok(None),
        }
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<u64, StorageError> {
        validate_key(key)?;
        validate_generic_value(value)?;
        let tx = self.begin_write()?;
        let mut table = tx.open_table(KV).map_err(|_| StorageError::Unavailable)?;
        let old = table
            .get(key)
            .map_err(|_| StorageError::Unavailable)?
            .map(|v| decode_versioned_record(v.value()).map(|record| record.0))
            .transpose()?;
        let version = old
            .map(|v| v.checked_add(1).ok_or(StorageError::VersionExhausted))
            .transpose()?
            .unwrap_or(1);
        let encoded = encode_versioned(version, value);
        table
            .insert(key, encoded.as_slice())
            .map_err(|_| StorageError::Unavailable)?;
        drop(table);
        tx.commit().map_err(|_| StorageError::Unavailable)?;
        Ok(version)
    }

    fn delete(&self, key: &[u8]) -> Result<bool, StorageError> {
        validate_key(key)?;
        let tx = self.begin_write()?;
        let mut table = tx.open_table(KV).map_err(|_| StorageError::Unavailable)?;
        let current = table
            .get(key)
            .map_err(|_| StorageError::Unavailable)?
            .map(|value| decode_versioned_record(value.value()))
            .transpose()?;
        let Some((version, Some(_))) = current else {
            drop(table);
            tx.commit().map_err(|_| StorageError::Unavailable)?;
            return Ok(false);
        };
        let next_version = version
            .checked_add(1)
            .ok_or(StorageError::VersionExhausted)?;
        let tombstone = encode_tombstone(next_version);
        table
            .insert(key, tombstone.as_slice())
            .map_err(|_| StorageError::Unavailable)?;
        drop(table);
        tx.commit().map_err(|_| StorageError::Unavailable)?;
        Ok(true)
    }

    fn list(
        &self,
        prefix: &[u8],
        limit: usize,
        cursor: Option<&[u8]>,
    ) -> Result<RecordPage, StorageError> {
        if prefix.len() > MAX_KEY_LEN || limit == 0 || limit > 10_000 {
            return Err(StorageError::InvalidInput);
        }
        let after = cursor.map(|c| decode_cursor(prefix, c)).transpose()?;
        let tx = self
            .database
            .begin_read()
            .map_err(|_| StorageError::Unavailable)?;
        let table = tx.open_table(KV).map_err(|_| StorageError::Unavailable)?;
        let mut records = Vec::with_capacity(limit.min(256));
        let mut last = None;
        let mut has_more = false;
        for entry in table.iter().map_err(|_| StorageError::Unavailable)? {
            let (key, value) = entry.map_err(|_| StorageError::Unavailable)?;
            let key = key.value();
            if !key.starts_with(prefix) || after.as_ref().is_some_and(|a| key <= a.as_slice()) {
                continue;
            }
            let (version, decoded) = decode_versioned_record(value.value())?;
            let Some(decoded) = decoded else {
                continue;
            };
            if records.len() == limit {
                has_more = true;
                break;
            }
            last = Some(key.to_vec());
            records.push(KvRecord {
                key: key.to_vec(),
                version,
                value: decoded,
            });
        }
        let next_cursor = if has_more {
            Some(encode_cursor(
                prefix,
                last.as_deref().ok_or(StorageError::InvalidCursor)?,
            )?)
        } else {
            None
        };
        Ok(RecordPage {
            records,
            next_cursor,
        })
    }

    fn compare_and_swap(
        &self,
        key: &[u8],
        expected_version: Option<u64>,
        replacement: Option<&[u8]>,
    ) -> Result<Option<u64>, StorageError> {
        let mutation = match replacement {
            Some(v) => Mutation::put(key.to_vec(), v.to_vec())?,
            None => Mutation::delete(key.to_vec())?,
        };
        let precondition = Precondition::new(key.to_vec(), expected_version)?;
        self.apply_batch(&[mutation], &[precondition])
            .map(|versions| versions[0])
    }

    fn apply_batch(
        &self,
        mutations: &[Mutation],
        preconditions: &[Precondition],
    ) -> Result<Vec<Option<u64>>, StorageError> {
        if mutations.is_empty() || mutations.len() != preconditions.len() {
            return Err(StorageError::InvalidInput);
        }
        for (index, mutation) in mutations.iter().enumerate() {
            validate_key(mutation.key())?;
            if let Mutation::Put { value, .. } = mutation {
                validate_generic_value(value)?;
            }
            if mutation.key() != preconditions[index].key.as_slice()
                || mutations[..index].iter().any(|m| m.key() == mutation.key())
            {
                return Err(StorageError::InvalidInput);
            }
        }

        let tx = self.begin_write()?;
        let mut table = tx.open_table(KV).map_err(|_| StorageError::Unavailable)?;
        for condition in preconditions {
            let actual = table
                .get(condition.key.as_slice())
                .map_err(|_| StorageError::Unavailable)?
                .map(|value| {
                    decode_versioned_record(value.value())
                        .map(|(version, value)| value.map(|_| version))
                })
                .transpose()?
                .flatten();
            if actual != condition.expected_version {
                return Err(StorageError::Conflict);
            }
        }

        let mut versions = Vec::with_capacity(mutations.len());
        for mutation in mutations {
            match mutation {
                Mutation::Put { key, value } => {
                    validate_value(value)?;
                    let prior = table
                        .get(key.as_slice())
                        .map_err(|_| StorageError::Unavailable)?
                        .map(|v| decode_versioned_record(v.value()).map(|record| record.0))
                        .transpose()?;
                    let version = prior
                        .map(|v| v.checked_add(1).ok_or(StorageError::VersionExhausted))
                        .transpose()?
                        .unwrap_or(1);
                    let encoded = encode_versioned(version, value);
                    table
                        .insert(key.as_slice(), encoded.as_slice())
                        .map_err(|_| StorageError::Unavailable)?;
                    versions.push(Some(version));
                }
                Mutation::Delete { key } => {
                    let current = table
                        .get(key.as_slice())
                        .map_err(|_| StorageError::Unavailable)?
                        .map(|value| decode_versioned_record(value.value()))
                        .transpose()?;
                    if let Some((version, Some(_))) = current {
                        let next_version = version
                            .checked_add(1)
                            .ok_or(StorageError::VersionExhausted)?;
                        let tombstone = encode_tombstone(next_version);
                        table
                            .insert(key.as_slice(), tombstone.as_slice())
                            .map_err(|_| StorageError::Unavailable)?;
                    }
                    versions.push(None);
                }
            }
        }
        drop(table);
        tx.commit().map_err(|_| StorageError::Unavailable)?;
        Ok(versions)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DependencyKind {
    Backup = 1,
    Snapshot = 2,
    RotationJob = 3,
}

impl NonceUsageLedger for RedbStore {
    fn reserve(
        &self,
        key_id: &KeyId,
        key_version: u64,
        config: NonceBudgetConfig,
    ) -> Result<NonceReservation, NonceLedgerError> {
        if key_version == 0 {
            return Err(NonceLedgerError::CorruptState);
        }
        let id = key_id.as_str().as_bytes();
        let id_len = u16::try_from(id.len()).map_err(|_| NonceLedgerError::CorruptState)?;
        let mut key = Vec::with_capacity(2 + id.len() + 8);
        key.extend_from_slice(&id_len.to_be_bytes());
        key.extend_from_slice(id);
        key.extend_from_slice(&key_version.to_be_bytes());

        let mut tx = self
            .database
            .begin_write()
            .map_err(|_| NonceLedgerError::Unavailable)?;
        tx.set_durability(Durability::Immediate)
            .map_err(|_| NonceLedgerError::Unavailable)?;
        let mut table = tx
            .open_table(NONCES)
            .map_err(|_| NonceLedgerError::Unavailable)?;
        let state = table
            .get(key.as_slice())
            .map_err(|_| NonceLedgerError::Unavailable)?
            .map(|v| decode_nonce_state(v.value()))
            .transpose()?;
        let (start, block, threshold) = state.unwrap_or((
            1,
            config.reservation_block_size().get(),
            config.rotation_threshold().get(),
        ));
        if block != config.reservation_block_size().get()
            || threshold != config.rotation_threshold().get()
        {
            return Err(NonceLedgerError::CorruptState);
        }
        let end = start
            .checked_add(block)
            .ok_or(NonceLedgerError::CounterExhausted)?;
        if start == 0 || end > MAX_GCM_INVOCATIONS || end - 1 > threshold {
            // Do not advance the high-water mark for a block that cannot be
            // issued under the immutable rotation policy. Repeated callers
            // fail against the same durable state instead of burning blocks.
            return Err(NonceLedgerError::CounterExhausted);
        }
        let encoded = encode_nonce_state(end, block, threshold);
        table
            .insert(key.as_slice(), encoded.as_slice())
            .map_err(|_| NonceLedgerError::Unavailable)?;
        drop(table);
        tx.commit().map_err(|_| NonceLedgerError::Unavailable)?;
        NonceReservation::new(start, end)
    }
}

impl KeyDependencyInventory for RedbStore {
    fn has_dependencies(
        &self,
        key_id: &KeyId,
        key_version: u64,
    ) -> Result<bool, KeyInventoryError> {
        let prefix = dependency_prefix(key_id.as_str(), key_version)
            .map_err(|_| KeyInventoryError::Unavailable)?;
        let tx = self
            .begin_write()
            .map_err(|_| KeyInventoryError::Unavailable)?;
        let meta = tx
            .open_table(META)
            .map_err(|_| KeyInventoryError::Unavailable)?;
        let marker = meta
            .get(INVENTORY_COMPLETE)
            .map_err(|_| KeyInventoryError::Unavailable)?
            .map(|v| v.value().to_vec())
            .ok_or(KeyInventoryError::Incomplete)?;
        if marker.as_slice() != [1] {
            return Err(KeyInventoryError::Incomplete);
        }
        drop(meta);
        let mut retired = tx
            .open_table(RETIRED_KEYS)
            .map_err(|_| KeyInventoryError::Unavailable)?;
        let already_retired = retired
            .get(prefix.as_slice())
            .map_err(|_| KeyInventoryError::Unavailable)?
            .is_some();
        let table = tx
            .open_table(DEPENDENCIES)
            .map_err(|_| KeyInventoryError::Unavailable)?;
        for entry in table.iter().map_err(|_| KeyInventoryError::Unavailable)? {
            let (key, _) = entry.map_err(|_| KeyInventoryError::Unavailable)?;
            if key.value().starts_with(&prefix) {
                if already_retired {
                    return Err(KeyInventoryError::Incomplete);
                }
                return Ok(true);
            }
        }
        drop(table);
        if !already_retired {
            retired
                .insert(prefix.as_slice(), &[1_u8][..])
                .map_err(|_| KeyInventoryError::Unavailable)?;
        }
        drop(retired);
        tx.commit().map_err(|_| KeyInventoryError::Unavailable)?;
        Ok(false)
    }
}

impl RotationStore for RedbStore {
    fn checkpoint(&self, job_id: &str) -> Result<Option<RotationCheckpoint>, RotationStoreError> {
        validate_job_id(job_id)?;
        let tx = self
            .database
            .begin_read()
            .map_err(|_| RotationStoreError::Unavailable)?;
        let table = tx
            .open_table(CHECKPOINTS)
            .map_err(|_| RotationStoreError::Unavailable)?;
        table
            .get(job_id.as_bytes())
            .map_err(|_| RotationStoreError::Unavailable)?
            .map(|v| decode_checkpoint(v.value()))
            .transpose()
    }

    fn list_page(
        &self,
        after: Option<&[u8]>,
        limit: std::num::NonZeroUsize,
    ) -> Result<RotationPage, RotationStoreError> {
        if after.is_some_and(|v| v.is_empty()) || limit.get() > 10_000 {
            return Err(RotationStoreError::InvalidCursor);
        }
        let tx = self
            .database
            .begin_read()
            .map_err(|_| RotationStoreError::Unavailable)?;
        let table = tx
            .open_table(BARRIER)
            .map_err(|_| RotationStoreError::Unavailable)?;
        let mut records = Vec::with_capacity(limit.get().min(256));
        let mut last = None;
        let mut has_more = false;
        for entry in table.iter().map_err(|_| RotationStoreError::Unavailable)? {
            let (key, value) = entry.map_err(|_| RotationStoreError::Unavailable)?;
            let path_bytes = key.value();
            validate_key(path_bytes).map_err(|_| RotationStoreError::CorruptState)?;
            if after.is_some_and(|cursor| path_bytes <= cursor) {
                continue;
            }
            if records.len() == limit.get() {
                has_more = true;
                break;
            }
            let path = CanonicalPath::new(path_bytes.to_vec())
                .map_err(|_| RotationStoreError::CorruptState)?;
            let record = RotationRecord::new(path, value.value().to_vec())
                .map_err(|_| RotationStoreError::CorruptState)?;
            last = Some(path_bytes.to_vec());
            records.push(record);
        }
        RotationPage::new(records, if has_more { last } else { None }, !has_more)
    }

    fn compare_and_swap_with_audit(
        &self,
        path: &CanonicalPath,
        expected_envelope: &[u8],
        replacement_envelope: &[u8],
        success_event: RotationAuditEvent,
        conflict_event: RotationAuditEvent,
    ) -> Result<bool, RotationStoreError> {
        if validate_key(path.as_bytes()).is_err()
            || validate_value(expected_envelope).is_err()
            || validate_value(replacement_envelope).is_err()
            || expected_envelope.is_empty()
            || BarrierEnvelope::decode(replacement_envelope).is_err()
            || success_event.job_id() != conflict_event.job_id()
        {
            return Err(RotationStoreError::CorruptState);
        }
        let tx = self
            .begin_write()
            .map_err(|_| RotationStoreError::Unavailable)?;
        let replacement = BarrierEnvelope::decode(replacement_envelope)
            .map_err(|_| RotationStoreError::CorruptState)?;
        ensure_key_version_not_retired(
            &tx,
            replacement.key_id().as_str(),
            replacement.key_version(),
        )
        .map_err(|_| RotationStoreError::CorruptState)?;
        let records = tx
            .open_table(BARRIER)
            .map_err(|_| RotationStoreError::Unavailable)?;
        let current = records
            .get(path.as_bytes())
            .map_err(|_| RotationStoreError::Unavailable)?
            .map(|v| v.value().to_vec());
        drop(records);
        let matched = current.as_deref() == Some(expected_envelope);
        if matched {
            update_live_dependency(
                &tx,
                path.as_bytes(),
                current.as_deref(),
                Some(replacement_envelope),
            )
            .map_err(|_| RotationStoreError::Unavailable)?;
            let mut records = tx
                .open_table(BARRIER)
                .map_err(|_| RotationStoreError::Unavailable)?;
            records
                .insert(path.as_bytes(), replacement_envelope)
                .map_err(|_| RotationStoreError::Unavailable)?;
            drop(records);
            append_audit(&tx, &success_event).map_err(|_| RotationStoreError::Unavailable)?;
        } else {
            append_audit(&tx, &conflict_event).map_err(|_| RotationStoreError::Unavailable)?;
        }
        tx.commit().map_err(|_| RotationStoreError::Unavailable)?;
        Ok(matched)
    }

    fn save_checkpoint_with_audit(
        &self,
        job_id: &str,
        checkpoint: RotationCheckpoint,
        event: RotationAuditEvent,
    ) -> Result<(), RotationStoreError> {
        validate_job_id(job_id)?;
        if event.job_id() != job_id || event.target_key_version() != checkpoint.target_key_version()
        {
            return Err(RotationStoreError::CorruptState);
        }
        let dependency = external_dependency_key(
            event.key_id(),
            event.target_key_version(),
            DependencyKind::RotationJob,
            job_id.as_bytes(),
        )
        .map_err(|_| RotationStoreError::CorruptState)?;
        let persist_dependency = match event.kind() {
            RotationAuditKind::Started | RotationAuditKind::Checkpointed
                if !checkpoint.is_complete() =>
            {
                true
            }
            RotationAuditKind::Completed if checkpoint.is_complete() => false,
            _ => return Err(RotationStoreError::CorruptState),
        };

        let encoded = encode_checkpoint(&checkpoint);
        let tx = self
            .begin_write()
            .map_err(|_| RotationStoreError::Unavailable)?;
        if persist_dependency {
            ensure_key_version_not_retired(&tx, event.key_id(), event.target_key_version())
                .map_err(|_| RotationStoreError::CorruptState)?;
        }
        let mut dependencies = tx
            .open_table(DEPENDENCIES)
            .map_err(|_| RotationStoreError::Unavailable)?;
        if persist_dependency {
            dependencies
                .insert(dependency.as_slice(), &[1_u8][..])
                .map_err(|_| RotationStoreError::Unavailable)?;
        } else {
            dependencies
                .remove(dependency.as_slice())
                .map_err(|_| RotationStoreError::Unavailable)?;
        }
        drop(dependencies);

        let mut table = tx
            .open_table(CHECKPOINTS)
            .map_err(|_| RotationStoreError::Unavailable)?;
        table
            .insert(job_id.as_bytes(), encoded.as_slice())
            .map_err(|_| RotationStoreError::Unavailable)?;
        drop(table);
        append_audit(&tx, &event).map_err(|_| RotationStoreError::Unavailable)?;
        tx.commit().map_err(|_| RotationStoreError::Unavailable)
    }
}

fn validate_job_id(value: &str) -> Result<(), RotationStoreError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(b))
    {
        return Err(RotationStoreError::CorruptState);
    }
    Ok(())
}
fn validate_key(key: &[u8]) -> Result<(), StorageError> {
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        return Err(StorageError::InvalidInput);
    }
    Ok(())
}
fn validate_value(value: &[u8]) -> Result<(), StorageError> {
    if value.len() > MAX_VALUE_LEN {
        return Err(StorageError::LimitExceeded);
    }
    Ok(())
}
fn is_barrier_envelope(value: &[u8]) -> bool {
    value.starts_with(BARRIER_ENVELOPE_MAGIC)
}
fn validate_generic_value(value: &[u8]) -> Result<(), StorageError> {
    validate_value(value)?;
    if is_barrier_envelope(value) {
        return Err(StorageError::InvalidInput);
    }
    Ok(())
}
const VALUE_PRESENT: u8 = 1;
const VALUE_TOMBSTONE: u8 = 0;

fn encode_versioned(version: u64, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + value.len());
    out.extend_from_slice(&version.to_be_bytes());
    out.push(VALUE_PRESENT);
    out.extend_from_slice(value);
    out
}

fn encode_tombstone(version: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.extend_from_slice(&version.to_be_bytes());
    out.push(VALUE_TOMBSTONE);
    out
}

/// Decodes a versioned record. A tombstone is represented by None but retains
/// its monotonically increasing version for future writes and CAS preconditions.
pub fn decode_versioned_record(input: &[u8]) -> Result<(u64, Option<Vec<u8>>), StorageError> {
    if input.len() < 9 {
        return Err(StorageError::CorruptRecord);
    }
    let version = u64::from_be_bytes(
        input[..8]
            .try_into()
            .map_err(|_| StorageError::CorruptRecord)?,
    );
    if version == 0 || input.len() - 9 > MAX_VALUE_LEN {
        return Err(StorageError::CorruptRecord);
    }
    match input[8] {
        VALUE_TOMBSTONE if input.len() == 9 => Ok((version, None)),
        VALUE_PRESENT => Ok((version, Some(input[9..].to_vec()))),
        _ => Err(StorageError::CorruptRecord),
    }
}

/// Decodes only a live record. Tombstones are not visible through KV reads.
pub fn decode_versioned(input: &[u8]) -> Result<StoredValue, StorageError> {
    let (version, value) = decode_versioned_record(input)?;
    let value = value.ok_or(StorageError::CorruptRecord)?;
    Ok(StoredValue { version, value })
}

pub fn encode_cursor(prefix: &[u8], last_key: &[u8]) -> Result<Vec<u8>, StorageError> {
    if last_key.is_empty() || !last_key.starts_with(prefix) {
        return Err(StorageError::InvalidCursor);
    }
    let length = u32::try_from(prefix.len()).map_err(|_| StorageError::InvalidCursor)?;
    let mut out = Vec::with_capacity(8 + prefix.len() + last_key.len());
    out.extend_from_slice(CURSOR_MAGIC);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(prefix);
    out.extend_from_slice(last_key);
    Ok(out)
}
pub fn decode_cursor(prefix: &[u8], cursor: &[u8]) -> Result<Vec<u8>, StorageError> {
    if cursor.len() < 9 || cursor.get(..4) != Some(CURSOR_MAGIC.as_slice()) {
        return Err(StorageError::InvalidCursor);
    }
    let length = u32::from_be_bytes(
        cursor[4..8]
            .try_into()
            .map_err(|_| StorageError::InvalidCursor)?,
    ) as usize;
    let offset = 8_usize
        .checked_add(length)
        .ok_or(StorageError::InvalidCursor)?;
    if cursor.len() <= offset || cursor.get(8..offset) != Some(prefix) {
        return Err(StorageError::InvalidCursor);
    }
    let last = cursor.get(offset..).ok_or(StorageError::InvalidCursor)?;
    if last.is_empty() || !last.starts_with(prefix) {
        return Err(StorageError::InvalidCursor);
    }
    Ok(last.to_vec())
}

/// Strictly decodes the durable nonce high-water mark and immutable policy.
pub fn decode_nonce_state(input: &[u8]) -> Result<(u64, u64, u64), NonceLedgerError> {
    if input.len() != 28 || input.get(..4) != Some(NONCE_MAGIC.as_slice()) {
        return Err(NonceLedgerError::CorruptState);
    }
    let high = u64::from_be_bytes(
        input[4..12]
            .try_into()
            .map_err(|_| NonceLedgerError::CorruptState)?,
    );
    let block = u64::from_be_bytes(
        input[12..20]
            .try_into()
            .map_err(|_| NonceLedgerError::CorruptState)?,
    );
    let threshold = u64::from_be_bytes(
        input[20..28]
            .try_into()
            .map_err(|_| NonceLedgerError::CorruptState)?,
    );
    if high == 0
        || block == 0
        || threshold == 0
        || threshold >= MAX_GCM_INVOCATIONS
        || block > threshold
    {
        return Err(NonceLedgerError::CorruptState);
    }
    Ok((high, block, threshold))
}
fn encode_nonce_state(high: u64, block: u64, threshold: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(28);
    out.extend_from_slice(NONCE_MAGIC);
    out.extend_from_slice(&high.to_be_bytes());
    out.extend_from_slice(&block.to_be_bytes());
    out.extend_from_slice(&threshold.to_be_bytes());
    out
}
fn dependency_prefix(id: &str, version: u64) -> Result<Vec<u8>, StorageError> {
    let bytes = id.as_bytes();
    let length = u16::try_from(bytes.len()).map_err(|_| StorageError::InvalidInput)?;
    if bytes.is_empty() || version == 0 {
        return Err(StorageError::InvalidInput);
    }
    let mut out = Vec::with_capacity(2 + bytes.len() + 8);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    out.extend_from_slice(&version.to_be_bytes());
    Ok(out)
}
fn ensure_key_version_not_retired(
    tx: &WriteTransaction,
    id: &str,
    version: u64,
) -> Result<(), StorageError> {
    let key = dependency_prefix(id, version)?;
    let table = tx
        .open_table(RETIRED_KEYS)
        .map_err(|_| StorageError::Unavailable)?;
    let retired = table
        .get(key.as_slice())
        .map_err(|_| StorageError::Unavailable)?
        .is_some();
    if retired {
        Err(StorageError::InvalidInput)
    } else {
        Ok(())
    }
}

fn external_dependency_key(
    id: &str,
    version: u64,
    kind: DependencyKind,
    resource: &[u8],
) -> Result<Vec<u8>, StorageError> {
    if resource.is_empty() || resource.len() > MAX_KEY_LEN {
        return Err(StorageError::InvalidInput);
    }
    let mut out = dependency_prefix(id, version)?;
    out.push(kind as u8);
    let length = u32::try_from(resource.len()).map_err(|_| StorageError::LimitExceeded)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(resource);
    Ok(out)
}
fn is_live_dependency(key: &[u8]) -> bool {
    if key.len() < 11 {
        return false;
    }
    let id_len = u16::from_be_bytes([key[0], key[1]]) as usize;
    let Some(kind_offset) = 2_usize.checked_add(id_len).and_then(|v| v.checked_add(8)) else {
        return false;
    };
    key.get(kind_offset) == Some(&0)
}

fn live_dependency_key(envelope: &[u8], path: &[u8]) -> Result<Vec<u8>, StorageError> {
    validate_key(path)?;
    let parsed = BarrierEnvelope::decode(envelope).map_err(|_| StorageError::CorruptRecord)?;
    let mut out = dependency_prefix(parsed.key_id().as_str(), parsed.key_version())?;
    out.push(0);
    let length = u32::try_from(path.len()).map_err(|_| StorageError::LimitExceeded)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(path);
    Ok(out)
}
fn update_live_dependency(
    tx: &WriteTransaction,
    path: &[u8],
    old: Option<&[u8]>,
    new: Option<&[u8]>,
) -> Result<(), StorageError> {
    let old_key = old.map(|v| live_dependency_key(v, path)).transpose()?;
    let new_key = new.map(|v| live_dependency_key(v, path)).transpose()?;
    let mut table = tx
        .open_table(DEPENDENCIES)
        .map_err(|_| StorageError::Unavailable)?;
    if let Some(key) = old_key {
        table
            .remove(key.as_slice())
            .map_err(|_| StorageError::Unavailable)?;
    }
    if let Some(key) = new_key {
        table
            .insert(key.as_slice(), &[1_u8][..])
            .map_err(|_| StorageError::Unavailable)?;
    }
    Ok(())
}
fn encode_checkpoint(checkpoint: &RotationCheckpoint) -> Vec<u8> {
    let cursor = checkpoint.cursor().unwrap_or_default();
    let mut out = Vec::with_capacity(17 + cursor.len());
    out.extend_from_slice(CHECKPOINT_MAGIC);
    out.extend_from_slice(&checkpoint.target_key_version().to_be_bytes());
    out.push(u8::from(checkpoint.is_complete()));
    out.extend_from_slice(&(cursor.len() as u32).to_be_bytes());
    out.extend_from_slice(cursor);
    out
}
/// Strictly decodes a durable resumable-rotation checkpoint.
pub fn decode_checkpoint(input: &[u8]) -> Result<RotationCheckpoint, RotationStoreError> {
    if input.len() < 17 || input.get(..4) != Some(CHECKPOINT_MAGIC.as_slice()) {
        return Err(RotationStoreError::CorruptState);
    }
    let target = u64::from_be_bytes(
        input[4..12]
            .try_into()
            .map_err(|_| RotationStoreError::CorruptState)?,
    );
    let complete = match input[12] {
        0 => false,
        1 => true,
        _ => return Err(RotationStoreError::CorruptState),
    };
    let length = u32::from_be_bytes(
        input[13..17]
            .try_into()
            .map_err(|_| RotationStoreError::CorruptState)?,
    ) as usize;
    if input.len()
        != 17_usize
            .checked_add(length)
            .ok_or(RotationStoreError::CorruptState)?
    {
        return Err(RotationStoreError::CorruptState);
    }
    let cursor = if length == 0 {
        None
    } else {
        Some(input[17..].to_vec())
    };
    RotationCheckpoint::new(target, cursor, complete)
}
fn append_audit(tx: &WriteTransaction, event: &RotationAuditEvent) -> Result<(), StorageError> {
    let encoded = encode_audit(event)?;
    let mut meta = tx.open_table(META).map_err(|_| StorageError::Unavailable)?;
    let current = meta
        .get(AUDIT_SEQUENCE)
        .map_err(|_| StorageError::Unavailable)?
        .map(|v| v.value().to_vec());
    let sequence = match current {
        Some(bytes) if bytes.len() == 8 => {
            u64::from_be_bytes(bytes.try_into().map_err(|_| StorageError::CorruptRecord)?)
        }
        Some(_) => return Err(StorageError::CorruptRecord),
        None => 0,
    };
    let next = sequence
        .checked_add(1)
        .ok_or(StorageError::VersionExhausted)?;
    let key = next.to_be_bytes();
    let mut audit = tx
        .open_table(AUDIT)
        .map_err(|_| StorageError::Unavailable)?;
    audit
        .insert(key.as_slice(), encoded.as_slice())
        .map_err(|_| StorageError::Unavailable)?;
    drop(audit);
    meta.insert(AUDIT_SEQUENCE, key.as_slice())
        .map_err(|_| StorageError::Unavailable)?;
    Ok(())
}
fn encode_audit(event: &RotationAuditEvent) -> Result<Vec<u8>, StorageError> {
    let job = event.job_id().as_bytes();
    let id = event.key_id().as_bytes();
    let jl = u16::try_from(job.len()).map_err(|_| StorageError::InvalidInput)?;
    let il = u16::try_from(id.len()).map_err(|_| StorageError::InvalidInput)?;
    let mut out = Vec::with_capacity(64 + job.len() + id.len());
    out.extend_from_slice(AUDIT_MAGIC);
    out.extend_from_slice(&jl.to_be_bytes());
    out.extend_from_slice(job);
    out.extend_from_slice(&il.to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&event.target_key_version().to_be_bytes());
    if let Some(v) = event.source_key_version() {
        out.push(1);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        out.push(0);
    }
    if let Some(fp) = event.path_fingerprint() {
        out.push(1);
        out.extend_from_slice(fp);
    } else {
        out.push(0);
    }
    out.push(match event.kind() {
        RotationAuditKind::Started => 0,
        RotationAuditKind::RecordReencrypted => 1,
        RotationAuditKind::RecordConflict => 2,
        RotationAuditKind::Checkpointed => 3,
        RotationAuditKind::Completed => 4,
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_crypto::barrier::{RotationAuditEvent, RotationAuditKind};
    use proptest::prelude::*;
    use std::num::NonZeroU64;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    static FILE_ID: AtomicU64 = AtomicU64::new(1);
    fn path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ferrum-storage-{}-{}.db",
            std::process::id(),
            FILE_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn remove(path: &Path) {
        let _ = std::fs::remove_file(path);
    }
    fn key_id() -> KeyId {
        KeyId::new("community/test-key").unwrap()
    }
    fn nonce_config() -> NonceBudgetConfig {
        NonceBudgetConfig::new(NonZeroU64::new(4).unwrap(), NonZeroU64::new(64).unwrap()).unwrap()
    }
    fn envelope(version: u64) -> Vec<u8> {
        BarrierEnvelope::new(
            key_id(),
            version,
            ferrum_crypto::SealedPayload {
                nonce: [version as u8; 12],
                ciphertext_and_tag: vec![0xAB; 16],
            },
        )
        .unwrap()
        .encode()
    }
    fn event(job: &str, kind: RotationAuditKind) -> RotationAuditEvent {
        RotationAuditEvent::new(job, &key_id(), 2, None, None, kind).unwrap()
    }

    #[test]
    fn nonce_high_water_and_immutable_policy_survive_reopen() {
        let file = path();
        {
            let store = RedbStore::open(&file).unwrap();
            let first = store.reserve(&key_id(), 1, nonce_config()).unwrap();
            assert_eq!((first.start(), first.end_exclusive()), (1, 5));
        }
        {
            let store = RedbStore::open(&file).unwrap();
            let second = store.reserve(&key_id(), 1, nonce_config()).unwrap();
            assert_eq!((second.start(), second.end_exclusive()), (5, 9));
            let changed =
                NonceBudgetConfig::new(NonZeroU64::new(8).unwrap(), NonZeroU64::new(64).unwrap())
                    .unwrap();
            assert_eq!(
                store.reserve(&key_id(), 1, changed),
                Err(NonceLedgerError::CorruptState)
            );
        }
        remove(&file);
    }

    #[test]
    fn nonce_ledger_refuses_block_past_rotation_threshold_without_advancing() {
        let file = path();
        let config =
            NonceBudgetConfig::new(NonZeroU64::new(4).unwrap(), NonZeroU64::new(12).unwrap())
                .unwrap();
        let store = RedbStore::open(&file).unwrap();

        for expected_start in [1, 5, 9] {
            let reservation = store.reserve(&key_id(), 8, config).unwrap();
            assert_eq!(reservation.start(), expected_start);
            assert_eq!(reservation.end_exclusive(), expected_start + 4);
        }
        assert_eq!(
            store.reserve(&key_id(), 8, config),
            Err(NonceLedgerError::CounterExhausted)
        );

        let key = {
            let id = key_id();
            let bytes = id.as_str().as_bytes();
            let mut key = Vec::with_capacity(2 + bytes.len() + 8);
            key.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            key.extend_from_slice(bytes);
            key.extend_from_slice(&8_u64.to_be_bytes());
            key
        };
        let high_water = {
            let tx = store.database.begin_read().unwrap();
            let table = tx.open_table(NONCES).unwrap();
            let value = table.get(key.as_slice()).unwrap().unwrap();
            decode_nonce_state(value.value()).unwrap().0
        };
        assert_eq!(high_water, 13);
        assert_eq!(
            store.reserve(&key_id(), 8, config),
            Err(NonceLedgerError::CounterExhausted)
        );
        drop(store);

        let reopened = RedbStore::open(&file).unwrap();
        assert_eq!(
            reopened.reserve(&key_id(), 8, config),
            Err(NonceLedgerError::CounterExhausted)
        );
        let tx = reopened.database.begin_read().unwrap();
        let table = tx.open_table(NONCES).unwrap();
        let value = table.get(key.as_slice()).unwrap().unwrap();
        assert_eq!(decode_nonce_state(value.value()).unwrap().0, 13);
        drop(table);
        drop(tx);
        drop(reopened);
        remove(&file);
    }

    #[test]
    fn empty_inventory_fences_late_dependencies_across_reopen() {
        let file = path();
        let record_path = CanonicalPath::new(b"kv/retired-version".to_vec()).unwrap();
        {
            let store = RedbStore::open(&file).unwrap();
            assert!(!store.has_dependencies(&key_id(), 44).unwrap());
            assert_eq!(
                store.put_encrypted(&record_path, &envelope(44)),
                Err(StorageError::InvalidInput)
            );
            assert_eq!(
                store.register_dependency(
                    "community/test-key",
                    44,
                    DependencyKind::Backup,
                    b"late-backup",
                ),
                Err(StorageError::InvalidInput)
            );
        }
        {
            let store = RedbStore::open(&file).unwrap();
            assert_eq!(
                store.register_dependency(
                    "community/test-key",
                    44,
                    DependencyKind::Snapshot,
                    b"late-snapshot",
                ),
                Err(StorageError::InvalidInput)
            );
            assert_eq!(
                store.put_encrypted(&record_path, &envelope(44)),
                Err(StorageError::InvalidInput)
            );
        }
        remove(&file);
    }

    #[test]
    fn retirement_fence_serializes_with_dependency_registration() {
        let file = path();
        let store = RedbStore::open(&file).unwrap();
        let checker = store.clone();
        let registrar = store.clone();
        let check = thread::spawn(move || checker.has_dependencies(&key_id(), 91).unwrap());
        let registration = thread::spawn(move || {
            registrar.register_dependency(
                "community/test-key",
                91,
                DependencyKind::Backup,
                b"racing-backup",
            )
        });
        let has_dependencies = check.join().unwrap();
        let registered = registration.join().unwrap();
        assert_eq!(has_dependencies, registered.is_ok());
        if registered.is_ok() {
            assert!(
                store
                    .remove_dependency(
                        "community/test-key",
                        91,
                        DependencyKind::Backup,
                        b"racing-backup",
                    )
                    .unwrap()
            );
        }
        drop(store);
        remove(&file);
    }

    #[test]
    fn generic_kv_rejects_fbe1_and_reconciliation_detects_legacy_value() {
        let file = path();
        {
            let db = Builder::new()
                .set_concurrency_mode(ConcurrencyMode::MultiWriter)
                .create(&file)
                .unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.set_durability(Durability::Immediate).unwrap();
            let mut table = tx.open_table(KV).unwrap();
            let encoded = encode_versioned(1, &envelope(1));
            table
                .insert(b"kv/legacy".as_slice(), encoded.as_slice())
                .unwrap();
            drop(table);
            tx.commit().unwrap();
        }

        let store = RedbStore::open(&file).unwrap();
        let protected = envelope(1);
        assert_eq!(
            store.put(b"kv/not-a-barrier-record", &protected),
            Err(StorageError::InvalidInput)
        );
        assert_eq!(
            Mutation::put(b"kv/batch".to_vec(), protected.clone()),
            Err(StorageError::InvalidInput)
        );
        let bypass = vec![Mutation::Put {
            key: b"kv/batch".to_vec(),
            value: protected,
        }];
        let conditions = vec![Precondition::new(b"kv/batch".to_vec(), None).unwrap()];
        assert_eq!(
            store.apply_batch(&bypass, &conditions),
            Err(StorageError::InvalidInput)
        );
        assert_eq!(
            store.has_dependencies(&key_id(), 1),
            Err(KeyInventoryError::Incomplete)
        );
        assert_eq!(
            store.confirm_inventory_reconciled(),
            Err(StorageError::CorruptRecord)
        );

        assert!(store.delete(b"kv/legacy").unwrap());
        store.confirm_inventory_reconciled().unwrap();
        assert!(!store.has_dependencies(&key_id(), 1).unwrap());
        drop(store);
        remove(&file);
    }

    #[test]
    fn encrypted_records_enforce_max_key_length() {
        let file = path();
        let store = RedbStore::open(&file).unwrap();
        let oversized = CanonicalPath::new(vec![b'x'; MAX_KEY_LEN + 1]).unwrap();
        assert_eq!(
            store.put_encrypted(&oversized, &envelope(1)),
            Err(StorageError::InvalidInput)
        );
        assert_eq!(
            store.delete_encrypted(&oversized),
            Err(StorageError::InvalidInput)
        );
        drop(store);
        remove(&file);
    }

    #[test]
    fn concurrent_nonce_reservations_are_disjoint_across_database_handles() {
        let file = path();
        let initial = RedbStore::open(&file).unwrap();
        drop(initial);

        let workers: Vec<_> = (0..12)
            .map(|_| {
                let file = file.clone();
                thread::spawn(move || {
                    let store = RedbStore::open(&file).unwrap();
                    store.reserve(&key_id(), 3, nonce_config()).unwrap()
                })
            })
            .collect();
        let mut blocks: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        blocks.sort_by_key(NonceReservation::start);
        for pair in blocks.windows(2) {
            assert_eq!(pair[0].end_exclusive(), pair[1].start());
        }
        remove(&file);
    }

    #[test]
    #[ignore = "invoked as a subprocess by nonce_reservations_are_disjoint_across_processes"]
    fn nonce_reservation_child_process() {
        let database = std::env::var_os("FERRUM_REDB_CHILD_DATABASE")
            .expect("parent test provides a database path");
        let store = RedbStore::open(database).unwrap();
        let reservation = store.reserve(&key_id(), 77, nonce_config()).unwrap();
        println!(
            "FERRUM_NONCE_RESERVATION={}:{}",
            reservation.start(),
            reservation.end_exclusive()
        );
    }

    #[test]
    fn nonce_reservations_are_disjoint_across_processes() {
        let file = path();
        let initial = RedbStore::open(&file).unwrap();
        drop(initial);

        let executable = std::env::current_exe().unwrap();
        let children: Vec<_> = (0..8)
            .map(|_| {
                Command::new(&executable)
                    .arg("--exact")
                    .arg("tests::nonce_reservation_child_process")
                    .arg("--ignored")
                    .arg("--nocapture")
                    .env("FERRUM_REDB_CHILD_DATABASE", &file)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();

        let mut reservations = Vec::with_capacity(children.len());
        for child in children {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "child process failed; stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            let marker = stdout
                .lines()
                .find_map(|line| line.split_once("FERRUM_NONCE_RESERVATION="))
                .map(|(_, value)| value)
                .expect("child prints its reservation");
            let (start, end) = marker.split_once(':').expect("reservation has two bounds");
            reservations.push((start.parse::<u64>().unwrap(), end.parse::<u64>().unwrap()));
        }

        reservations.sort_unstable_by_key(|reservation| reservation.0);
        for pair in reservations.windows(2) {
            assert_eq!(pair[0].1, pair[1].0);
        }
        remove(&file);
    }

    #[test]
    fn kv_cas_batches_and_conflict_rollback() {
        let file = path();
        let store = RedbStore::open(&file).unwrap();
        assert_eq!(store.put(b"kv/a", b"one").unwrap(), 1);
        assert_eq!(
            store
                .compare_and_swap(b"kv/a", Some(1), Some(b"two"))
                .unwrap(),
            Some(2)
        );
        assert_eq!(
            store.compare_and_swap(b"kv/a", Some(1), Some(b"stale")),
            Err(StorageError::Conflict)
        );
        let mutations = vec![
            Mutation::put(b"kv/b".to_vec(), b"two".to_vec()).unwrap(),
            Mutation::put(b"kv/c".to_vec(), b"three".to_vec()).unwrap(),
        ];
        let conditions = vec![
            Precondition::new(b"kv/b".to_vec(), None).unwrap(),
            Precondition::new(b"kv/c".to_vec(), None).unwrap(),
        ];
        assert_eq!(
            store.apply_batch(&mutations, &conditions).unwrap(),
            vec![Some(1), Some(1)]
        );
        let fail = vec![
            Precondition::new(b"kv/b".to_vec(), Some(77)).unwrap(),
            Precondition::new(b"kv/c".to_vec(), None).unwrap(),
        ];
        assert_eq!(
            store.apply_batch(&mutations, &fail),
            Err(StorageError::Conflict)
        );
        assert_eq!(store.get(b"kv/c").unwrap().unwrap().value(), b"three");
        drop(store);
        remove(&file);
    }

    #[test]
    fn delete_and_recreate_never_reuses_a_cas_version() {
        let file = path();
        let store = RedbStore::open(&file).unwrap();

        assert_eq!(store.put(b"kv/aba", b"first").unwrap(), 1);
        assert!(store.delete(b"kv/aba").unwrap());
        assert!(store.get(b"kv/aba").unwrap().is_none());

        assert_eq!(
            store.compare_and_swap(b"kv/aba", Some(1), Some(b"stale")),
            Err(StorageError::Conflict)
        );

        assert_eq!(
            store
                .compare_and_swap(b"kv/aba", None, Some(b"recreated"))
                .unwrap(),
            Some(3)
        );
        assert_eq!(
            store.compare_and_swap(b"kv/aba", Some(1), Some(b"stale-again")),
            Err(StorageError::Conflict)
        );
        assert_eq!(
            store.compare_and_swap(b"kv/aba", Some(3), None).unwrap(),
            None
        );
        assert!(store.get(b"kv/aba").unwrap().is_none());
        assert_eq!(
            store
                .compare_and_swap(b"kv/aba", None, Some(b"recreated-again"))
                .unwrap(),
            Some(5)
        );
        assert_eq!(
            store.compare_and_swap(b"kv/aba", Some(3), Some(b"stale-after-cas-delete")),
            Err(StorageError::Conflict)
        );
        let live = store.get(b"kv/aba").unwrap().unwrap();
        assert_eq!(live.version(), 5);
        assert_eq!(live.value(), b"recreated-again");

        drop(store);
        remove(&file);
    }

    #[test]
    fn prefix_pagination_and_cursor_prefix_binding() {
        let file = path();
        let store = RedbStore::open(&file).unwrap();
        for key in [b"kv/a".as_slice(), b"kv/b", b"kv/c", b"other/a"] {
            store.put(key, key).unwrap();
        }
        assert!(store.delete(b"kv/b").unwrap());
        store.put(b"kv/d", b"kv/d").unwrap();
        let first = store.list(b"kv/", 2, None).unwrap();
        assert_eq!(first.records().len(), 2);
        assert_eq!(first.records()[0].key(), b"kv/a");
        assert_eq!(first.records()[1].key(), b"kv/c");
        let second = store.list(b"kv/", 2, first.next_cursor()).unwrap();
        assert_eq!(second.records().len(), 1);
        assert_eq!(second.records()[0].key(), b"kv/d");
        assert_eq!(
            store.list(b"other/", 2, first.next_cursor()),
            Err(StorageError::InvalidCursor)
        );
        drop(store);
        remove(&file);
    }

    #[test]
    fn rotation_checkpoint_registers_and_releases_target_key_dependency() {
        let file = path();
        {
            let store = RedbStore::open(&file).unwrap();
            store
                .save_checkpoint_with_audit(
                    "job-fence",
                    RotationCheckpoint::new(2, None, false).unwrap(),
                    event("job-fence", RotationAuditKind::Started),
                )
                .unwrap();
        }
        {
            let store = RedbStore::open(&file).unwrap();
            assert!(store.has_dependencies(&key_id(), 2).unwrap());
            store
                .save_checkpoint_with_audit(
                    "job-fence",
                    RotationCheckpoint::new(2, None, true).unwrap(),
                    event("job-fence", RotationAuditKind::Completed),
                )
                .unwrap();
        }
        {
            let store = RedbStore::open(&file).unwrap();
            assert!(!store.has_dependencies(&key_id(), 2).unwrap());
            assert_eq!(
                store.register_dependency(
                    "community/test-key",
                    2,
                    DependencyKind::Snapshot,
                    b"late-snapshot",
                ),
                Err(StorageError::InvalidInput)
            );
        }
        remove(&file);
    }

    #[test]
    fn rotation_cas_audit_checkpoint_and_dependencies_survive_reopen() {
        let file = path();
        let record_path = CanonicalPath::new(b"kv/rotation".to_vec()).unwrap();
        let old = envelope(1);
        let new = envelope(2);
        {
            let store = RedbStore::open(&file).unwrap();
            store.put_encrypted(&record_path, &old).unwrap();
            assert!(store.has_dependencies(&key_id(), 1).unwrap());
            assert!(
                store
                    .compare_and_swap_with_audit(
                        &record_path,
                        &old,
                        &new,
                        event("job-1", RotationAuditKind::RecordReencrypted),
                        event("job-1", RotationAuditKind::RecordConflict),
                    )
                    .unwrap()
            );
            assert!(!store.has_dependencies(&key_id(), 1).unwrap());
            assert!(store.has_dependencies(&key_id(), 2).unwrap());
            store
                .save_checkpoint_with_audit(
                    "job-1",
                    RotationCheckpoint::new(2, Some(b"kv/rotation".to_vec()), false).unwrap(),
                    event("job-1", RotationAuditKind::Checkpointed),
                )
                .unwrap();
            assert_eq!(store.audit_count().unwrap(), 2);
        }
        {
            let store = RedbStore::open(&file).unwrap();
            let checkpoint = store.checkpoint("job-1").unwrap().unwrap();
            assert_eq!(checkpoint.target_key_version(), 2);
            assert_eq!(checkpoint.cursor(), Some(b"kv/rotation".as_slice()));
            assert_eq!(store.audit_count().unwrap(), 2);
        }
        remove(&file);
    }

    #[test]
    fn inventory_reconciliation_rebuilds_missing_live_index() {
        let file = path();
        {
            let db = Builder::new()
                .set_concurrency_mode(ConcurrencyMode::MultiWriter)
                .create(&file)
                .unwrap();
            let mut tx = db.begin_write().unwrap();
            tx.set_durability(Durability::Immediate).unwrap();
            let mut table = tx.open_table(BARRIER).unwrap();
            table
                .insert(b"kv/legacy".as_slice(), envelope(1).as_slice())
                .unwrap();
            drop(table);
            tx.commit().unwrap();
        }
        {
            let store = RedbStore::open(&file).unwrap();
            assert_eq!(
                store.has_dependencies(&key_id(), 1),
                Err(KeyInventoryError::Incomplete)
            );
            store.confirm_inventory_reconciled().unwrap();
            assert!(store.has_dependencies(&key_id(), 1).unwrap());
        }
        remove(&file);
    }

    #[test]
    fn backup_and_snapshot_dependencies_block_retirement() {
        let file = path();
        let store = RedbStore::open(&file).unwrap();
        store
            .register_dependency("community/test-key", 1, DependencyKind::Backup, b"backup-1")
            .unwrap();
        assert!(store.has_dependencies(&key_id(), 1).unwrap());
        assert!(
            store
                .remove_dependency("community/test-key", 1, DependencyKind::Backup, b"backup-1")
                .unwrap()
        );
        assert!(!store.has_dependencies(&key_id(), 1).unwrap());
        drop(store);
        remove(&file);
    }

    #[test]
    fn dropping_uncommitted_transaction_does_not_publish_partial_write() {
        let file = path();
        {
            let store = RedbStore::open(&file).unwrap();
            let tx = store.begin_write().unwrap();
            let mut table = tx.open_table(KV).unwrap();
            table
                .insert(b"kv/uncommitted".as_slice(), b"not-versioned".as_slice())
                .unwrap();
            drop(table);
            drop(tx);
        }
        {
            let store = RedbStore::open(&file).unwrap();
            assert!(store.get(b"kv/uncommitted").unwrap().is_none());
        }
        remove(&file);
    }

    proptest! {
        #[test]
        fn cursor_roundtrips_for_arbitrary_prefixes(
            prefix in prop::collection::vec(any::<u8>(), 0..48),
            suffix in prop::collection::vec(any::<u8>(), 1..48)
        ) {
            let mut key = prefix.clone();
            key.extend_from_slice(&suffix);
            let cursor = encode_cursor(&prefix, &key).unwrap();
            prop_assert_eq!(decode_cursor(&prefix, &cursor).unwrap(), key);
        }

        #[test]
        fn malformed_version_records_fail_closed(input in prop::collection::vec(any::<u8>(), 0..32)) {
            if input.len() < 9 {
                prop_assert_eq!(decode_versioned_record(&input), Err(StorageError::CorruptRecord));
            }
        }
    }
}
