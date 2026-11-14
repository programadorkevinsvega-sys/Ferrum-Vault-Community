//! Explicit, feature-gated AWS KMS auto-unseal adapter.
//!
//! The optional aws-kms feature contains the official AWS SDK for Rust adapter.
//! Credentials are resolved by the SDK's default provider chain (environment,
//! shared config/profile, web identity and workload/instance roles). No credential
//! values are hardcoded by Ferrum; the SDK resolves them externally. Unit tests use an in-memory
//! fake and no AWS account or credentials.

use std::fmt;

use async_trait::async_trait;
#[cfg(feature = "aws-kms")]
use aws_sdk_kms::primitives::Blob;
#[cfg(feature = "aws-kms")]
use aws_sdk_kms::types::{KeyManagerType, KeySpec, KeyState, KeyUsageType};
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
    InvalidKeyConfiguration,
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

/// Thin asynchronous bridge used by the provider-neutral unsealer.
/// The production implementation is the feature-gated official AWS SDK
/// adapter below; tests inject an in-memory fake. Implementations must use a
/// symmetric KMS key and pass exactly one encryption-context pair:
/// FerrumContextSHA256V1 = context_sha256_hex.
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
/// mandatory; there is no default provider, and no local fallback.
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
        if kms_region_from_key_arn(&key_id).is_none() || key_version == 0 {
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
        if root.is_empty() || root.len() > 4096 {
            return Err(UnsealerError::InvalidWrappedRoot);
        }
        let context = kms_context_sha256_hex(ceremony_id);
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

        let context = kms_context_sha256_hex(request.expected_ceremony_id());
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
        KmsApiError::InvalidKeyConfiguration => UnsealerError::InvalidConfiguration,
    }
}

fn kms_region_from_key_arn(value: &str) -> Option<&str> {
    let mut parts = value.split(':');
    if parts.next()? != "arn" {
        return None;
    }
    if !matches!(parts.next()?, "aws" | "aws-us-gov" | "aws-cn") {
        return None;
    }
    if parts.next()? != "kms" {
        return None;
    }
    let region = parts.next()?;
    if region.is_empty()
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return None;
    }
    let account = parts.next()?;
    if account.len() != 12 || !account.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let resource = parts.next()?;
    let key_id = resource.strip_prefix("key/")?;
    if key_id.is_empty() || key_id.contains('/') || parts.next().is_some() {
        return None;
    }
    Some(region)
}

/// FVC1-compatible context containing tenant=root, purpose=seal-root and the
/// public ceremony identifier. Only its SHA-256 digest is sent to KMS because
/// KMS encryption context is plaintext audit metadata.
pub fn kms_context_sha256_hex(ceremony_id: [u8; 16]) -> String {
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


/// Official AWS SDK for Rust implementation of the KMS bridge.
///
/// The SDK's default credential provider chain is used. Region is taken from
/// the configured KMS key ARN, rather than silently falling back to a
/// different region. The constructor calls DescribeKey and rejects keys that
/// are not enabled symmetric ENCRYPT_DECRYPT keys.
#[cfg(feature = "aws-kms")]
#[derive(Clone)]
pub struct AwsSdkKmsApi {
    client: aws_sdk_kms::Client,
    key_arn: String,
    region: String,
}

#[cfg(feature = "aws-kms")]
impl AwsSdkKmsApi {
    /// Loads credentials and region through the official SDK configuration
    /// chain, pins the service client to the ARN's region, and validates the
    /// key with DescribeKey before returning.
    pub async fn from_default_chain_for_key_arn(
        key_arn: impl Into<String>,
    ) -> Result<Self, UnsealerError> {
        let key_arn = key_arn.into();
        let region = kms_region_from_key_arn(&key_arn)
            .ok_or(UnsealerError::InvalidConfiguration)?
            .to_owned();

        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_kms::config::Region::new(region.clone()))
            .load()
            .await;
        let client = aws_sdk_kms::Client::new(&sdk_config);
        let api = Self {
            client,
            key_arn,
            region,
        };
        api.validate_key().await?;
        Ok(api)
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    pub fn key_arn(&self) -> &str {
        &self.key_arn
    }

    async fn validate_key(&self) -> Result<(), UnsealerError> {
        let output = self
            .client
            .describe_key()
            .key_id(&self.key_arn)
            .send()
            .await
            .map_err(map_sdk_error)?;
        let metadata = output
            .key_metadata()
            .ok_or(UnsealerError::InvalidConfiguration)?;

        if metadata.arn() != Some(self.key_arn.as_str())
            || metadata.key_manager() != Some(&KeyManagerType::Customer)
            || metadata.key_usage() != Some(&KeyUsageType::EncryptDecrypt)
            || metadata.key_spec() != Some(&KeySpec::SymmetricDefault)
        {
            return Err(UnsealerError::InvalidConfiguration);
        }

        if !metadata.enabled() || metadata.key_state() != Some(&KeyState::Enabled) {
            return Err(UnsealerError::ProviderUnavailable);
        }

        Ok(())
    }
}

#[cfg(feature = "aws-kms")]
#[async_trait]
impl AwsKmsApi for AwsSdkKmsApi {
    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        context_sha256_hex: &str,
    ) -> Result<KmsCiphertext, KmsApiError> {
        if key_id != self.key_arn || plaintext.is_empty() || plaintext.len() > 4096 {
            return Err(KmsApiError::InvalidKeyConfiguration);
        }

        let output = self
            .client
            .encrypt()
            .key_id(&self.key_arn)
            .plaintext(Blob::new(plaintext))
            .encryption_context(AWS_KMS_CONTEXT_KEY, context_sha256_hex)
            .send()
            .await
            .map_err(map_sdk_error)?;

        let ciphertext = output
            .ciphertext_blob()
            .ok_or(KmsApiError::Failure)?
            .as_ref()
            .to_vec();
        let returned_key_id = output
            .key_id()
            .unwrap_or(self.key_arn.as_str())
            .to_owned();

        Ok(KmsCiphertext {
            key_id: returned_key_id,
            ciphertext,
        })
    }

    async fn decrypt(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        context_sha256_hex: &str,
    ) -> Result<KmsPlaintext, KmsApiError> {
        if key_id != self.key_arn || ciphertext.is_empty() {
            return Err(KmsApiError::InvalidKeyConfiguration);
        }

        let output = self
            .client
            .decrypt()
            .key_id(&self.key_arn)
            .ciphertext_blob(Blob::new(ciphertext))
            .encryption_context(AWS_KMS_CONTEXT_KEY, context_sha256_hex)
            .send()
            .await
            .map_err(map_sdk_error)?;

        let plaintext = output.plaintext().ok_or(KmsApiError::Failure)?;
        let returned_key_id = output
            .key_id()
            .unwrap_or(self.key_arn.as_str())
            .to_owned();

        Ok(KmsPlaintext::new(
            returned_key_id,
            Zeroizing::new(plaintext.as_ref().to_vec()),
        ))
    }
}

#[cfg(feature = "aws-kms")]
fn map_sdk_error<E, R>(error: aws_sdk_kms::error::SdkError<E, R>) -> KmsApiError
where
    E: aws_sdk_kms::error::ProvideErrorMetadata,
{
    if let Some(code) = error.as_service_error().and_then(|service| service.code()) {
        return match code {
            "AccessDeniedException" => KmsApiError::AccessDenied,
            "InvalidCiphertextException" | "IncorrectKeyException" => {
                KmsApiError::InvalidCiphertext
            }
            "DisabledException" | "KMSInvalidStateException" | "NotFoundException" => {
                KmsApiError::KeyUnavailable
            }
            "ThrottlingException" | "LimitExceededException" => KmsApiError::Throttled,
            "DependencyTimeoutException" => KmsApiError::Timeout,
            _ => KmsApiError::Failure,
        };
    }

    match error {
        aws_sdk_kms::error::SdkError::TimeoutError(_) => KmsApiError::Timeout,
        aws_sdk_kms::error::SdkError::DispatchFailure(_)
        | aws_sdk_kms::error::SdkError::ResponseError(_) => KmsApiError::Transport,
        aws_sdk_kms::error::SdkError::ConstructionFailure(_) => KmsApiError::Failure,
        aws_sdk_kms::error::SdkError::ServiceError(_) => KmsApiError::Failure,
        _ => KmsApiError::Failure,
    }
}

/// Creates an AWS-backed unsealer using the SDK's standard credential chain.
/// Region is pinned from the key ARN, and DescribeKey is checked up front.
#[cfg(feature = "aws-kms")]
impl AwsKmsUnsealer<AwsSdkKmsApi> {
    pub async fn from_environment(
        key_arn: impl Into<String>,
        key_version: u64,
    ) -> Result<Self, UnsealerError> {
        let key_arn = key_arn.into();
        let client = AwsSdkKmsApi::from_default_chain_for_key_arn(&key_arn).await?;
        Self::new(client, key_arn, key_version)
    }

    pub fn region(&self) -> &str {
        self.client.region()
    }

    pub fn configured_key_arn(&self) -> &str {
        self.client.key_arn()
    }
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
        assert_eq!(
            super::map_kms_error(KmsApiError::InvalidKeyConfiguration),
            UnsealerError::InvalidConfiguration
        );
    }


    #[test]
    fn kms_encrypt_rejects_plaintext_larger_than_symmetric_kms_limit() {
        let root = vec![0x5A; 4097];
        let shares = make_shares(&root);
        let adapter = AwsKmsUnsealer::new(FakeKms::default(), KEY_ID, 1).unwrap();
        assert_eq!(
            block_on(adapter.encrypt_root_for_unseal(&root, shares[0].ceremony_id())).err(),
            Some(UnsealerError::InvalidWrappedRoot)
        );
    }

    #[test]
    fn key_arn_parser_requires_a_regional_customer_key_arn() {
        assert_eq!(super::kms_region_from_key_arn(KEY_ID), Some("us-east-1"));
        assert!(super::kms_region_from_key_arn("alias/ferrum-root").is_none());
        assert!(super::kms_region_from_key_arn("12345678-1234-1234-1234-123456789012").is_none());
        assert!(super::kms_region_from_key_arn(
            "arn:aws:kms:us-east-1:12345678901:key/12345678-1234-1234-1234-123456789012"
        )
        .is_none());
        assert!(super::kms_region_from_key_arn(
            "arn:aws:kms:us-east-1:123456789012:alias/ferrum-root"
        )
        .is_none());
    }

    #[test]
    fn context_digest_is_fixed_width_and_ceremony_bound() {
        let first = super::kms_context_sha256_hex([0x11; 16]);
        let second = super::kms_context_sha256_hex([0x22; 16]);
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn invalid_kms_configuration_fails_closed() {
        assert!(AwsKmsUnsealer::new(FakeKms::default(), "", 1).is_err());
        assert!(AwsKmsUnsealer::new(FakeKms::default(), "alias/ferrum-root", 1).is_err());
        assert!(AwsKmsUnsealer::new(FakeKms::default(), KEY_ID, 0).is_err());
        assert_eq!(
            AwsKmsUnsealer::new(FakeKms::default(), KEY_ID, 1)
                .unwrap()
                .key_id(),
            KEY_ID
        );
    }
}
