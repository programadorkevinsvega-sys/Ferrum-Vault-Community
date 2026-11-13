//! Key-management provider contract and canonical public envelopes.
//!
//! This module defines the provider boundary only. Cloud KMS adapters, the seal
//! lifecycle, key hierarchy orchestration, rotation policy and durable nonce
//! accounting belong to later Phase 1 subphases.

use std::fmt;

use async_trait::async_trait;
use zeroize::Zeroizing;

const ENVELOPE_MAGIC: &[u8; 4] = b"FVK1";
const ENVELOPE_VERSION: u16 = 1;
const CONTEXT_MAGIC: &[u8; 4] = b"FVC1";
const CONTEXT_VERSION: u16 = 1;
const COMMUNITY_TENANT_ID: &[u8] = b"root";

/// Typed failures at the key-management boundary. Display text never includes
/// key material, plaintext, authenticated context or ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyManagementError {
    InvalidInput,
    InvalidKeyId,
    InvalidAlgorithm,
    InvalidContext,
    InvalidWrappedKey,
    UnsupportedEnvelopeVersion(u16),
    KeyNotFound,
    KeyVersionUnavailable,
    UnsupportedAlgorithm,
    AuthenticationFailed,
    ProviderUnavailable,
    ProviderFailure,
}

impl fmt::Display for KeyManagementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid key-management input",
            Self::InvalidKeyId => "invalid key identifier",
            Self::InvalidAlgorithm => "invalid wrapping algorithm identifier",
            Self::InvalidContext => "invalid key-management context",
            Self::InvalidWrappedKey => "invalid wrapped-key envelope",
            Self::UnsupportedEnvelopeVersion(version) => {
                return write!(
                    formatter,
                    "unsupported wrapped-key envelope version {version}"
                );
            }
            Self::KeyNotFound => "wrapping key not found",
            Self::KeyVersionUnavailable => "wrapping key version unavailable",
            Self::UnsupportedAlgorithm => "unsupported wrapping algorithm",
            Self::AuthenticationFailed => "wrapped-key authentication failed",
            Self::ProviderUnavailable => "key-management provider unavailable",
            Self::ProviderFailure => "key-management provider operation failed",
        })
    }
}

impl std::error::Error for KeyManagementError {}

/// Validated provider key identifier; interpretation belongs to the provider.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(value: impl Into<String>) -> Result<Self, KeyManagementError> {
        let value = value.into();
        validate_identifier(&value).map_err(|_| KeyManagementError::InvalidKeyId)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Stable identifier for the algorithm that produced an envelope.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AlgorithmId(String);

impl AlgorithmId {
    pub fn new(value: impl Into<String>) -> Result<Self, KeyManagementError> {
        let value = value.into();
        validate_identifier(&value).map_err(|_| KeyManagementError::InvalidAlgorithm)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AlgorithmId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn validate_identifier(value: &str) -> Result<(), ()> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > usize::from(u16::MAX)
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/+-".contains(byte))
    {
        return Err(());
    }
    Ok(())
}

/// Purpose class for the key being wrapped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPurpose {
    SealRoot,
    KeyringKey,
    DataEncryptionKey,
}

impl KeyPurpose {
    const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::SealRoot => b"seal-root",
            Self::KeyringKey => b"keyring-key",
            Self::DataEncryptionKey => b"data-encryption-key",
        }
    }
}

/// Immutable, canonically encoded authenticated context.
///
/// Community is single-tenant, so tenant id is fixed to root. The context
/// binds purpose and caller-supplied canonical scope. It is distinct from the
/// storage-barrier AAD schema in ADR-0004.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyContext {
    encoded: Vec<u8>,
}

impl KeyContext {
    /// Encodes FVC1, u16-BE version, then tenant id, purpose and canonical scope
    /// as three u32-BE length-prefixed byte strings in this fixed order.
    pub fn new(purpose: KeyPurpose, canonical_scope: &[u8]) -> Result<Self, KeyManagementError> {
        if canonical_scope.is_empty() {
            return Err(KeyManagementError::InvalidContext);
        }

        let mut encoded = Vec::new();
        encoded.extend_from_slice(CONTEXT_MAGIC);
        encoded.extend_from_slice(&CONTEXT_VERSION.to_be_bytes());
        append_u32_field(&mut encoded, COMMUNITY_TENANT_ID)
            .map_err(|_| KeyManagementError::InvalidContext)?;
        append_u32_field(&mut encoded, purpose.as_bytes())
            .map_err(|_| KeyManagementError::InvalidContext)?;
        append_u32_field(&mut encoded, canonical_scope)
            .map_err(|_| KeyManagementError::InvalidContext)?;
        Ok(Self { encoded })
    }

    /// Returns the canonical bytes providers must authenticate verbatim.
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

impl fmt::Debug for KeyContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyContext")
            .field("encoded_len", &self.encoded.len())
            .finish()
    }
}

/// Versioned envelope returned by KeyManagementProvider::wrap.
/// Debug output deliberately omits ciphertext.
#[derive(Clone, Eq, PartialEq)]
pub struct WrappedKey {
    key_id: KeyId,
    key_version: u64,
    algorithm: AlgorithmId,
    ciphertext: Vec<u8>,
}

impl WrappedKey {
    pub fn new(
        key_id: KeyId,
        key_version: u64,
        algorithm: AlgorithmId,
        ciphertext: Vec<u8>,
    ) -> Result<Self, KeyManagementError> {
        if key_version == 0 || ciphertext.is_empty() || u32::try_from(ciphertext.len()).is_err() {
            return Err(KeyManagementError::InvalidWrappedKey);
        }
        Ok(Self {
            key_id,
            key_version,
            algorithm,
            ciphertext,
        })
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }
    pub fn key_version(&self) -> u64 {
        self.key_version
    }
    pub fn algorithm(&self) -> &AlgorithmId {
        &self.algorithm
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Canonical FVK1: magic[4], version[u16-BE], key-id length[u16-BE],
    /// key id, key version[u64-BE], algorithm length[u16-BE], algorithm,
    /// ciphertext length[u32-BE], ciphertext. No trailing bytes are valid.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(ENVELOPE_MAGIC);
        encoded.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&(self.key_id.0.len() as u16).to_be_bytes());
        encoded.extend_from_slice(self.key_id.0.as_bytes());
        encoded.extend_from_slice(&self.key_version.to_be_bytes());
        encoded.extend_from_slice(&(self.algorithm.0.len() as u16).to_be_bytes());
        encoded.extend_from_slice(self.algorithm.0.as_bytes());
        encoded.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.ciphertext);
        encoded
    }

    /// Strictly decodes one complete canonical envelope.
    pub fn decode(input: &[u8]) -> Result<Self, KeyManagementError> {
        let mut reader = Reader::new(input);
        if reader.take(4)? != ENVELOPE_MAGIC {
            return Err(KeyManagementError::InvalidWrappedKey);
        }

        let version = reader.read_u16()?;
        if version != ENVELOPE_VERSION {
            return Err(KeyManagementError::UnsupportedEnvelopeVersion(version));
        }

        let key_id_length = reader.read_u16()?;
        let key_id_bytes = reader.read_ascii(key_id_length)?;
        let key_id = KeyId::new(key_id_bytes).map_err(|_| KeyManagementError::InvalidWrappedKey)?;
        let key_version = reader.read_u64()?;
        let algorithm_length = reader.read_u16()?;
        let algorithm_bytes = reader.read_ascii(algorithm_length)?;
        let algorithm =
            AlgorithmId::new(algorithm_bytes).map_err(|_| KeyManagementError::InvalidWrappedKey)?;
        let ciphertext_len = usize::try_from(reader.read_u32()?)
            .map_err(|_| KeyManagementError::InvalidWrappedKey)?;
        let ciphertext = reader.take(ciphertext_len)?.to_vec();

        if !reader.is_empty() {
            return Err(KeyManagementError::InvalidWrappedKey);
        }
        Self::new(key_id, key_version, algorithm, ciphertext)
    }
}

impl fmt::Debug for WrappedKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WrappedKey")
            .field("key_id", &self.key_id)
            .field("key_version", &self.key_version)
            .field("algorithm", &self.algorithm)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

fn append_u32_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ()> {
    let length = u32::try_from(value.len()).map_err(|_| ())?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], KeyManagementError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(KeyManagementError::InvalidWrappedKey)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(KeyManagementError::InvalidWrappedKey)?;
        self.offset = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, KeyManagementError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, KeyManagementError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, KeyManagementError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_ascii(&mut self, length: u16) -> Result<String, KeyManagementError> {
        let bytes = self.take(usize::from(length))?;
        if !bytes.is_ascii() {
            return Err(KeyManagementError::InvalidWrappedKey);
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| KeyManagementError::InvalidWrappedKey)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.input.len()
    }
}

/// Dynamic asynchronous key-wrapping boundary.
///
/// Implementations cryptographically bind context bytes and envelope key-id,
/// key-version and algorithm metadata to the protected ciphertext; validate
/// metadata, reject unknown algorithms/versions, and fail closed. Dropping a
/// future cancels the
/// caller's wait but cannot promise that a remote provider rolled back an
/// accepted operation. Implementations must never expose partial plaintext or
/// an incomplete envelope. Callers must treat cancelled remote outcomes as
/// unknown and follow provider-specific retry semantics.
#[async_trait]
pub trait KeyManagementProvider: Send + Sync {
    async fn wrap(
        &self,
        key_id: &KeyId,
        plaintext: &[u8],
        context: &KeyContext,
    ) -> Result<WrappedKey, KeyManagementError>;

    async fn unwrap(
        &self,
        wrapped: &WrappedKey,
        context: &KeyContext,
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagementError>;
}

#[cfg(test)]
mod tests {
    use super::{AlgorithmId, KeyContext, KeyId, KeyManagementError, KeyPurpose, WrappedKey};

    #[test]
    fn identifiers_are_strict_ascii_tokens() {
        assert!(KeyId::new("kms/key-01").is_ok());
        assert!(AlgorithmId::new("AES-256-GCM").is_ok());
        assert_eq!(KeyId::new(""), Err(KeyManagementError::InvalidKeyId));
        assert_eq!(
            KeyId::new("../secret"),
            Err(KeyManagementError::InvalidKeyId)
        );
        assert_eq!(
            AlgorithmId::new("AES 256 GCM"),
            Err(KeyManagementError::InvalidAlgorithm)
        );
        assert_eq!(
            AlgorithmId::new("é"),
            Err(KeyManagementError::InvalidAlgorithm)
        );
    }

    #[test]
    fn context_encoding_is_deterministic_and_domain_separated() {
        let first = KeyContext::new(KeyPurpose::DataEncryptionKey, b"keys/app/primary").unwrap();
        let second = KeyContext::new(KeyPurpose::DataEncryptionKey, b"keys/app/primary").unwrap();
        let other_purpose = KeyContext::new(KeyPurpose::KeyringKey, b"keys/app/primary").unwrap();
        let other_scope =
            KeyContext::new(KeyPurpose::DataEncryptionKey, b"keys/app/secondary").unwrap();
        assert_eq!(first, second);
        assert_ne!(first, other_purpose);
        assert_ne!(first, other_scope);
        assert!(first.as_bytes().starts_with(b"FVC1"));
        assert!(KeyContext::new(KeyPurpose::SealRoot, b"").is_err());
    }

    #[test]
    fn wire_envelope_round_trips_canonically() {
        let envelope = sample_envelope();
        let encoded = envelope.encode();
        let decoded = WrappedKey::decode(&encoded).expect("decode succeeds");
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.encode(), encoded);
    }

    #[test]
    fn decoder_rejects_every_truncation_and_trailing_data() {
        let encoded = sample_envelope().encode();
        for end in 0..encoded.len() {
            assert!(
                WrappedKey::decode(&encoded[..end]).is_err(),
                "prefix ending at {end} unexpectedly decoded"
            );
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            WrappedKey::decode(&trailing),
            Err(KeyManagementError::InvalidWrappedKey)
        );
    }

    #[test]
    fn decoder_rejects_unknown_versions_and_invalid_metadata() {
        let encoded = sample_envelope().encode();
        let mut unknown_version = encoded.clone();
        unknown_version[4..6].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            WrappedKey::decode(&unknown_version),
            Err(KeyManagementError::UnsupportedEnvelopeVersion(2))
        );
        let mut zero_version = encoded.clone();
        zero_version[14..22].copy_from_slice(&0_u64.to_be_bytes());
        assert_eq!(
            WrappedKey::decode(&zero_version),
            Err(KeyManagementError::InvalidWrappedKey)
        );
        let mut bad_magic = encoded;
        bad_magic[0] ^= 0x80;
        assert_eq!(
            WrappedKey::decode(&bad_magic),
            Err(KeyManagementError::InvalidWrappedKey)
        );
    }

    #[test]
    fn deterministic_property_sweep_preserves_canonical_round_trips() {
        let mut state = 0xD1B5_4A32_D192_ED03_u64;
        for index in 0..2_000_u64 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let key_id = KeyId::new(format!("provider/key-{index}")).unwrap();
            let algorithm = AlgorithmId::new("AES-256-GCM").unwrap();
            let ciphertext_len = (state as usize % 256) + 1;
            let ciphertext = (0..ciphertext_len)
                .map(|offset| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    (state >> (offset % 32)) as u8
                })
                .collect();
            let wrapped =
                WrappedKey::new(key_id, (state | 1).max(1), algorithm, ciphertext).unwrap();
            let encoded = wrapped.encode();
            let decoded = WrappedKey::decode(&encoded).expect("generated envelope decodes");
            assert_eq!(decoded, wrapped);
            assert_eq!(decoded.encode(), encoded);
        }
    }

    #[test]
    fn provider_failures_have_non_sensitive_diagnostics() {
        let unavailable = KeyManagementError::ProviderUnavailable;
        let failed = KeyManagementError::ProviderFailure;
        assert_eq!(
            unavailable.to_string(),
            "key-management provider unavailable"
        );
        assert_eq!(
            failed.to_string(),
            "key-management provider operation failed"
        );
        assert!(!unavailable.to_string().contains("secret"));
    }

    fn sample_envelope() -> WrappedKey {
        WrappedKey::new(
            KeyId::new("community/keyring-v1").unwrap(),
            7,
            AlgorithmId::new("AES-256-GCM").unwrap(),
            vec![0xA5; 48],
        )
        .unwrap()
    }
}
