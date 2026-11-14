//! Explicit, feature-gated AWS KMS auto-unseal adapter.
//!
//! This module intentionally has no AWS SDK or credential-provider dependency.
//! The host application injects a narrow client implementation, allowing its
//! chosen AWS SDK version, region and credential chain to remain outside the
//! Ferrum core. Unit tests use an in-memory fake and no AWS credentials.

use std::fmt;

use async_trait::async_trait;
use aws_lc_rs::digest::{self, SHA256};
use zeroize::Zeroizing;

use crate::unsealer::{UnsealRequest, UnsealSource, Unsealer, UnsealerError, WrappedRootEnvelope};

pub const AWS_KMS_CONTEXT_KEY: &str = "FerrumContextSHA256V1";
pub const AWS_KMS_ALGORITHM: &str = "AWS-KMS";

/// Categorized failures from the host application's AWS KMS client bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KmsApiError {
    AccessDenied,
    InvalidCiphertext,
    KeyUnavailable,
    Throttled,
    Timeout,
    Transport,
    Failure,
}

impl fmt::Display for KmsApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AWS KMS operation failed")
    }
}

impl std::error::Error for KmsApiError {}

/// Ciphertext returned by the injected KMS Encrypt operation.
pub struct KmsCiphertext {
    pub key_id: String,
    pub ciphertext: Vec<u8>,
}

/// Plaintext returned by the injected KMS Decrypt operation.
pub struct KmsPlaintext {
    pub key_id: String,
    pub plaintext: Zeroizing<Vec<u8>>,
}

impl KmsPlaintext {
    pub fn new(key_id: impl Into<String>, plaintext: Zeroizing<Vec<u8>>) -> Self {
        Self {
            key_id: key_id.into(),
            plaintext,
        }
    }
}

impl fmt::Debug for KmsPlaintext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KmsPlaintext")
            .field("key_id", &self.key_id)
            .field("plaintext_len", &self.plaintext.len())
            .field("plaintext", &"redacted")
            .finish()
    }
}

/// Thin asynchronous bridge implemented by the host application's AWS SDK
/// client. Implementations must use a symmetric KMS key and pass exactly one
/// encryption-context pair: FerrumContextSHA256V1 = context_sha256_hex.
#[async_trait]
pub trait AwsKmsApi: Send + Sync {
    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        context_sha256_hex: &str,
    ) -> Result<KmsCiphertext, KmsApiError>;

    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        context_sha256_hex: &str,
    ) -> Result<KmsPlaintext, KmsApiError>;
}

/// Opt-in adapter. The configured KMS key ARN and envelope version are
/// mandatory; there is no default, implicit credential chain or local fallback.
pub struct AwsKmsUnsealer<C> {
    client: C,
    key_id: String,
    key_version: u64,
}

impl<C: AwsKmsApi> AwsKmsUnsealer<C> {
    pub fn new(
        client: C,
        key_id: impl Into<String>,
        key_version: u64,
    ) -> Result<Self, UnsealerError> {
        let key_id = key_id.into();
        if !valid_kms_key_id(&key_id) || key_version == 0 {
            return Err(UnsealerError::InvalidConfiguration);
        }
        Ok(Self {
            client,
            key_id,
            key_version,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Produces a provider-wrapped root for a ceremony already authorized by
    /// its caller. This helper only performs KMS encryption; it is not
    /// generate-root or root rotation and must not replace their 2-of-3 gate.
    pub async fn encrypt_root_for_unseal(
        &self,
        root: &[u8],
        ceremony_id: [u8; 16],
    ) -> Result<WrappedRootEnvelope, UnsealerError> {
        if root.is_empty() {
            return Err(UnsealerError::InvalidWrappedRoot);
        }
        let context = encryption_context(ceremony_id);
        let encrypted = self
            .client
            .encrypt(&self.key_id, root, &context)
            .await
            .map_err(map_kms_error)?;
        if encrypted.key_id != self.key_id || encrypted.ciphertext.is_empty() {
            return Err(UnsealerError::AuthenticationFailed);
        }
        WrappedRootEnvelope::new(self.key_id.clone(), self.key_version, encrypted.ciphertext)
    }
}

#[async_trait]
impl<C: AwsKmsApi> Unsealer for AwsKmsUnsealer<C> {
    async fn unseal(
        &self,
        request: UnsealRequest<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, UnsealerError> {
        let wrapped = match request.source() {
            UnsealSource::Wrapped(wrapped) => wrapped,
            UnsealSource::Shamir(_) => return Err(UnsealerError::InvalidSource),
        };
        if wrapped.key_id() != self.key_id || wrapped.key_version() != self.key_version {
            return Err(UnsealerError::AuthenticationFailed);
        }

        let context = encryption_context(request.expected_ceremony_id());
        let decrypted = self
            .client
            .decrypt(&self.key_id, wrapped.ciphertext(), &context)
            .await
            .map_err(map_kms_error)?;
        if decrypted.key_id != self.key_id || decrypted.plaintext.is_empty() {
            return Err(UnsealerError::AuthenticationFailed);
        }
        Ok(decrypted.plaintext)
    }
}

fn map_kms_error(error: KmsApiError) -> UnsealerError {
    match error {
        KmsApiError::AccessDenied => UnsealerError::AccessDenied,
        KmsApiError::InvalidCiphertext => UnsealerError::AuthenticationFailed,
        KmsApiError::KeyUnavailable | KmsApiError::Throttled | KmsApiError::Transport => {
            UnsealerError::ProviderUnavailable
        }
        KmsApiError::Timeout => UnsealerError::ProviderTimeout,
        KmsApiError::Failure => UnsealerError::ProviderFailure,
    }
}

fn valid_kms_key_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 2048
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/+-".contains(byte))
}

/// FVC1-compatible context containing tenant=root, purpose=seal-root and the
/// public ceremony identifier. Only its SHA-256 digest is sent to KMS because
/// KMS encryption context is plaintext audit metadata.
fn encryption_context(ceremony_id: [u8; 16]) -> String {
    let mut encoded = Vec::with_capacity(64);
    encoded.extend_from_slice(b"FVC1");
    encoded.extend_from_slice(&1_u16.to_be_bytes());
    append_context_field(&mut encoded, b"root");
    append_context_field(&mut encoded, b"seal-root");
    append_context_field(&mut encoded, &ceremony_id);

    let digest = digest::digest(&SHA256, &encoded);
    let mut output = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        use fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn append_context_field(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("short context field");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::{AwsKmsApi, AwsKmsUnsealer, KmsApiError, KmsCiphertext, KmsPlaintext};
    use crate::{
        RootQuorumOperation, RootQuorumPolicy, SealController, SealError, SealStatus,
        UnsealRequest, UnsealSource, Unsealer, UnsealerError, WrappedRootEnvelope,
    };
    use async_trait::async_trait;
    use ferrum_recovery::{RecoveryPolicy, RecoveryShare, split_secret};
    use std::collections::HashMap;
    use std::future::Future;
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};
    use zeroize::Zeroizing;

    const KEY_ID: &str =
        "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012";

    struct FakeEntry {
        key_id: String,
        context: String,
        plaintext: Zeroizing<Vec<u8>>,
    }

    #[derive(Default)]
    struct FakeState {
        next_id: u64,
        entries: HashMap<Vec<u8>, FakeEntry>,
        failure: Option<KmsApiError>,
    }

    #[derive(Default)]
    struct FakeKms {
        state: Mutex<FakeState>,
    }

    impl FakeKms {
        fn set_failure(&self, failure: Option<KmsApiError>) {
            self.state.lock().unwrap().failure = failure;
        }
    }

    #[async_trait]
    impl AwsKmsApi for FakeKms {
        async fn encrypt(
            &self,
            key_id: &str,
            plaintext: &[u8],
            context_sha256_hex: &str,
        ) -> Result<KmsCiphertext, KmsApiError> {
            let mut state = self.state.lock().unwrap();
            if let Some(failure) = state.failure {
                return Err(failure);
            }
            state.next_id = state.next_id.checked_add(1).ok_or(KmsApiError::Failure)?;
            let ciphertext = state.next_id.to_be_bytes().to_vec();
            state.entries.insert(
                ciphertext.clone(),
                FakeEntry {
                    key_id: key_id.to_owned(),
                    context: context_sha256_hex.to_owned(),
                    plaintext: Zeroizing::new(plaintext.to_vec()),
                },
            );
            Ok(KmsCiphertext {
                key_id: key_id.to_owned(),
                ciphertext,
            })
        }

        async fn decrypt(
            &self,
            key_id: &str,
            ciphertext: &[u8],
            context_sha256_hex: &str,
        ) -> Result<KmsPlaintext, KmsApiError> {
            let state = self.state.lock().unwrap();
            if let Some(failure) = state.failure {
                return Err(failure);
            }
            let entry = state
                .entries
                .get(ciphertext)
                .ok_or(KmsApiError::InvalidCiphertext)?;
            if entry.key_id != key_id || entry.context != context_sha256_hex {
                return Err(KmsApiError::InvalidCiphertext);
            }
            Ok(KmsPlaintext::new(
                entry.key_id.clone(),
                Zeroizing::new(entry.plaintext.to_vec()),
            ))
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("in-memory KMS fake unexpectedly yielded"),
        }
    }

    fn make_shares(root: &[u8]) -> Vec<RecoveryShare> {
        split_secret(root, RecoveryPolicy::new(2, 3).unwrap()).unwrap()
    }

    fn sealed_controller(shares: &[RecoveryShare], configure_quorum: bool) -> SealController {
        let controller = SealController::new();
        if configure_quorum {
            controller
                .configure_root_quorum(RootQuorumPolicy::new(2, 3).unwrap())
                .unwrap();
        }
        let token = controller
            .issue_bootstrap_token(std::time::Duration::from_secs(60))
            .unwrap();
        controller.bootstrap(&token, &shares[..2]).unwrap();
        controller
    }

    #[test]
    fn fake_kms_auto_unseal_binds_the_ceremony_and_keeps_root_quorum_separate() {
        let root = b"synthetic root used by the in-memory KMS test";
        let shares = make_shares(root);
        let controller = sealed_controller(&shares, true);
        let fake = FakeKms::default();
        let adapter = AwsKmsUnsealer::new(fake, KEY_ID, 1).unwrap();
        let wrapped =
            block_on(adapter.encrypt_root_for_unseal(root, shares[0].ceremony_id())).unwrap();

        block_on(controller.unseal_with(&adapter, UnsealSource::Wrapped(&wrapped))).unwrap();
        assert_eq!(controller.snapshot().status, SealStatus::Unsealed);
        assert_eq!(
            controller.with_root_key(|value| value.to_vec()).unwrap(),
            root
        );

        for operation in [
            RootQuorumOperation::GenerateRoot,
            RootQuorumOperation::RotateRoot,
            RootQuorumOperation::RevokeRoot,
        ] {
            assert_eq!(
                controller.with_root_quorum(operation, &shares[..1], |_| true),
                Err(SealError::RootQuorumRejected)
            );
            assert!(
                controller
                    .with_root_quorum(operation, &shares[..2], |context| {
                        context.operation == operation
                    })
                    .unwrap()
            );
        }
    }

    #[test]
    fn missing_root_operation_configuration_still_fails_after_kms_unseal() {
        let root = b"synthetic root with missing operation policy";
        let shares = make_shares(root);
        let controller = sealed_controller(&shares, false);
        let adapter = AwsKmsUnsealer::new(FakeKms::default(), KEY_ID, 1).unwrap();
        let wrapped =
            block_on(adapter.encrypt_root_for_unseal(root, shares[0].ceremony_id())).unwrap();
        block_on(controller.unseal_with(&adapter, UnsealSource::Wrapped(&wrapped))).unwrap();

        assert_eq!(
            controller.with_root_quorum(RootQuorumOperation::GenerateRoot, &shares[..2], |_| ()),
            Err(SealError::QuorumNotConfigured)
        );
    }

    #[test]
    fn denied_decrypt_leaves_the_controller_sealed_without_implicit_fallback() {
        let root = b"synthetic root for denied decrypt";
        let shares = make_shares(root);
        let controller = sealed_controller(&shares, true);
        let fake = FakeKms::default();
        let adapter = AwsKmsUnsealer::new(fake, KEY_ID, 1).unwrap();
        let wrapped =
            block_on(adapter.encrypt_root_for_unseal(root, shares[0].ceremony_id())).unwrap();
        // This is a test-only fault injection into the same fake KMS state.
        adapter.client.set_failure(Some(KmsApiError::AccessDenied));

        assert_eq!(
            block_on(controller.unseal_with(&adapter, UnsealSource::Wrapped(&wrapped))),
            Err(SealError::UnsealRejected)
        );
        assert_eq!(controller.snapshot().status, SealStatus::Sealed);

        // Manual recovery works only as a separate, explicit operator action.
        controller.unseal(&shares[..2]).unwrap();
        assert_eq!(controller.snapshot().status, SealStatus::Unsealed);
    }

    #[test]
    fn kms_context_prevents_ciphertext_reuse_across_ceremonies() {
        let first_root = b"synthetic first KMS ceremony root";
        let first_shares = make_shares(first_root);
        let second_shares = make_shares(b"synthetic second KMS ceremony root");
        let controller = sealed_controller(&second_shares, false);
        let adapter = AwsKmsUnsealer::new(FakeKms::default(), KEY_ID, 1).unwrap();
        let wrapped =
            block_on(adapter.encrypt_root_for_unseal(first_root, first_shares[0].ceremony_id()))
                .unwrap();

        assert_eq!(
            block_on(controller.unseal_with(&adapter, UnsealSource::Wrapped(&wrapped))),
            Err(SealError::UnsealRejected)
        );
        assert_eq!(controller.snapshot().status, SealStatus::Sealed);
    }

    #[test]
    fn changed_key_metadata_is_rejected_before_calling_kms() {
        let root = b"synthetic root for key metadata test";
        let shares = make_shares(root);
        let controller = sealed_controller(&shares, false);
        let adapter = AwsKmsUnsealer::new(FakeKms::default(), KEY_ID, 1).unwrap();
        let wrong_key = WrappedRootEnvelope::new(
            "arn:aws:kms:us-east-1:111122223333:key/ffffffff-ffff-ffff-ffff-ffffffffffff",
            1,
            vec![1, 2, 3],
        )
        .unwrap();
        assert_eq!(
            block_on(controller.unseal_with(&adapter, UnsealSource::Wrapped(&wrong_key))),
            Err(SealError::UnsealRejected)
        );
        let wrong_version = WrappedRootEnvelope::new(KEY_ID, 2, vec![1, 2, 3]).unwrap();
        assert_eq!(
            block_on(controller.unseal_with(&adapter, UnsealSource::Wrapped(&wrong_version))),
            Err(SealError::UnsealRejected)
        );
        assert_eq!(controller.snapshot().status, SealStatus::Sealed);
    }

    #[test]
    fn kms_timeout_is_typed_and_leaves_the_controller_sealed() {
        let root = b"synthetic root for timeout mapping";
        let shares = make_shares(root);
        let controller = sealed_controller(&shares, false);
        let fake = FakeKms::default();
        let adapter = AwsKmsUnsealer::new(fake, KEY_ID, 1).unwrap();
        let wrapped =
            block_on(adapter.encrypt_root_for_unseal(root, shares[0].ceremony_id())).unwrap();
        adapter.client.set_failure(Some(KmsApiError::Timeout));
        assert_eq!(
            block_on(adapter.unseal(UnsealRequest::from_wrapped(
                shares[0].ceremony_id(),
                &wrapped
            )))
            .err(),
            Some(UnsealerError::ProviderTimeout)
        );
        assert_eq!(
            block_on(controller.unseal_with(&adapter, UnsealSource::Wrapped(&wrapped))),
            Err(SealError::UnsealRejected)
        );
        assert_eq!(controller.snapshot().status, SealStatus::Sealed);
    }

    #[test]
    fn kms_errors_map_to_non_sensitive_provider_classes() {
        use crate::UnsealerError;

        assert_eq!(
            super::map_kms_error(KmsApiError::AccessDenied),
            UnsealerError::AccessDenied
        );
        assert_eq!(
            super::map_kms_error(KmsApiError::InvalidCiphertext),
            UnsealerError::AuthenticationFailed
        );
        assert_eq!(
            super::map_kms_error(KmsApiError::KeyUnavailable),
            UnsealerError::ProviderUnavailable
        );
        assert_eq!(
            super::map_kms_error(KmsApiError::Throttled),
            UnsealerError::ProviderUnavailable
        );
        assert_eq!(
            super::map_kms_error(KmsApiError::Transport),
            UnsealerError::ProviderUnavailable
        );
        assert_eq!(
            super::map_kms_error(KmsApiError::Timeout),
            UnsealerError::ProviderTimeout
        );
        assert_eq!(
            super::map_kms_error(KmsApiError::Failure),
            UnsealerError::ProviderFailure
        );
    }

    #[test]
    fn invalid_kms_configuration_fails_closed() {
        assert!(AwsKmsUnsealer::new(FakeKms::default(), "", 1).is_err());
        assert!(AwsKmsUnsealer::new(FakeKms::default(), KEY_ID, 0).is_err());
    }
}
