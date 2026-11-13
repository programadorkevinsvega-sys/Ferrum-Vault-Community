use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use async_trait::async_trait;
use ferrum_crypto::{
    Aes256GcmProvider, CryptoError, SealedPayload,
    kmp::{
        AlgorithmId, KeyContext, KeyId, KeyManagementError, KeyManagementProvider,
        KeyPurpose, WrappedKey,
    },
};
use zeroize::Zeroizing;

struct TestProvider {
    key_id: KeyId,
    algorithm: AlgorithmId,
    key_version: u64,
    cipher: Aes256GcmProvider,
}

impl TestProvider {
    fn new() -> Self {
        Self {
            key_id: KeyId::new("test/local-kek").unwrap(),
            algorithm: AlgorithmId::new("AES-256-GCM").unwrap(),
            key_version: 7,
            cipher: Aes256GcmProvider::new(&[0x42; 32]).unwrap(),
        }
    }

    fn recognizes_key(&self, key_id: &KeyId) -> bool {
        key_id == &self.key_id || key_id.as_str() == "test/key-alias"
    }
}

#[async_trait]
impl KeyManagementProvider for TestProvider {
    async fn wrap(
        &self,
        key_id: &KeyId,
        plaintext: &[u8],
        context: &KeyContext,
    ) -> Result<WrappedKey, KeyManagementError> {
        if !self.recognizes_key(key_id) {
            return Err(KeyManagementError::KeyNotFound);
        }
        if plaintext.is_empty() {
            return Err(KeyManagementError::InvalidInput);
        }

        let aad = authenticated_aad(context, key_id, self.key_version, &self.algorithm);
        let sealed = self.cipher.seal(&aad, plaintext).map_err(map_crypto_error)?;
        let mut ciphertext = Vec::with_capacity(12 + sealed.ciphertext_and_tag.len());
        ciphertext.extend_from_slice(&sealed.nonce);
        ciphertext.extend_from_slice(&sealed.ciphertext_and_tag);

        WrappedKey::new(key_id.clone(), self.key_version, self.algorithm.clone(), ciphertext)
    }

    async fn unwrap(
        &self,
        wrapped: &WrappedKey,
        context: &KeyContext,
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagementError> {
        if !self.recognizes_key(wrapped.key_id()) {
            return Err(KeyManagementError::KeyNotFound);
        }
        if wrapped.key_version() != self.key_version {
            return Err(KeyManagementError::KeyVersionUnavailable);
        }
        if wrapped.algorithm() != &self.algorithm {
            return Err(KeyManagementError::UnsupportedAlgorithm);
        }
        if wrapped.ciphertext().len() < 12 + 16 {
            return Err(KeyManagementError::InvalidWrappedKey);
        }

        let mut nonce = [0_u8; 12];
        nonce.copy_from_slice(&wrapped.ciphertext()[..12]);
        let sealed = SealedPayload {
            nonce,
            ciphertext_and_tag: wrapped.ciphertext()[12..].to_vec(),
        };
        let aad = authenticated_aad(
            context,
            wrapped.key_id(),
            wrapped.key_version(),
            wrapped.algorithm(),
        );
        let plaintext = self.cipher.open(&aad, &sealed).map_err(map_crypto_error)?;
        Ok(Zeroizing::new(plaintext))
    }
}

/// Test-only encoding to ensure both context and envelope metadata are bound
/// into the AEAD operation. Production providers use their provider-specific
/// authenticated mechanism but must preserve the same binding guarantee.
fn authenticated_aad(
    context: &KeyContext,
    key_id: &KeyId,
    key_version: u64,
    algorithm: &AlgorithmId,
) -> Vec<u8> {
    let mut aad = b"Ferrum-KMP-AAD-v1".to_vec();
    aad.extend_from_slice(context.as_bytes());
    for field in [key_id.as_str().as_bytes(), algorithm.as_str().as_bytes()] {
        aad.extend_from_slice(&(field.len() as u32).to_be_bytes());
        aad.extend_from_slice(field);
    }
    aad.extend_from_slice(&key_version.to_be_bytes());
    aad
}

fn map_crypto_error(error: CryptoError) -> KeyManagementError {
    match error {
        CryptoError::AuthenticationFailed => KeyManagementError::AuthenticationFailed,
        CryptoError::InvalidKey | CryptoError::EncryptionFailed => {
            KeyManagementError::ProviderFailure
        }
    }
}

fn run_ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test provider unexpectedly yielded"),
    }
}

fn key_context(scope: &[u8]) -> KeyContext {
    KeyContext::new(KeyPurpose::DataEncryptionKey, scope).unwrap()
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn contract_is_object_safe_and_send_sync() {
    assert_send_sync::<TestProvider>();
    let provider = TestProvider::new();
    let object: &dyn KeyManagementProvider = &provider;
    assert_eq!(
        object as *const dyn KeyManagementProvider as *const (),
        &provider as *const TestProvider as *const ()
    );
}

#[test]
fn wrap_unwrap_authenticates_the_exact_context() {
    let provider = TestProvider::new();
    let key_id = KeyId::new("test/local-kek").unwrap();
    let context = key_context(b"keys/application/primary");
    let plaintext = [0x5A; 32];
    let wrapped = run_ready(provider.wrap(&key_id, &plaintext, &context)).unwrap();
    assert_eq!(wrapped.key_id(), &key_id);
    assert_eq!(wrapped.key_version(), 7);
    assert_eq!(wrapped.algorithm().as_str(), "AES-256-GCM");
    assert_eq!(
        run_ready(provider.unwrap(&wrapped, &context)).unwrap().as_slice(),
        plaintext
    );

    let wrong_context = key_context(b"keys/application/secondary");
    assert_eq!(
        run_ready(provider.unwrap(&wrapped, &wrong_context)),
        Err(KeyManagementError::AuthenticationFailed)
    );
}

#[test]
fn every_context_scope_byte_is_authenticated() {
    let provider = TestProvider::new();
    let key_id = KeyId::new("test/local-kek").unwrap();
    let scope = b"keys/application/primary";
    let canonical_context = key_context(scope);
    let wrapped = run_ready(provider.wrap(&key_id, &[0x77; 32], &canonical_context)).unwrap();

    for index in 0..scope.len() {
        let mut changed = scope.to_vec();
        changed[index] ^= 0x01;
        let changed_context = key_context(&changed);
        assert_eq!(
            run_ready(provider.unwrap(&wrapped, &changed_context)),
            Err(KeyManagementError::AuthenticationFailed),
            "scope byte {index} was not authenticated"
        );
    }
}

#[test]
fn envelope_metadata_is_cryptographically_bound() {
    let provider = TestProvider::new();
    let context = key_context(b"keys/application/primary");
    let wrapped = run_ready(provider.wrap(
        &provider.key_id,
        &[0x33; 32],
        &context,
    )).unwrap();

    let alias = KeyId::new("test/key-alias").unwrap();
    let redirected = WrappedKey::new(
        alias,
        wrapped.key_version(),
        wrapped.algorithm().clone(),
        wrapped.ciphertext().to_vec(),
    ).unwrap();
    assert_eq!(
        run_ready(provider.unwrap(&redirected, &context)),
        Err(KeyManagementError::AuthenticationFailed)
    );
}

#[test]
fn provider_metadata_failures_are_typed_and_fail_closed() {
    let provider = TestProvider::new();
    let context = key_context(b"keys/application/primary");
    let wrong_key_id = KeyId::new("test/unknown-kek").unwrap();
    assert_eq!(
        run_ready(provider.wrap(&wrong_key_id, &[0x33; 32], &context)),
        Err(KeyManagementError::KeyNotFound)
    );

    let wrapped = run_ready(provider.wrap(&provider.key_id, &[0x33; 32], &context)).unwrap();
    let wrong_version = WrappedKey::new(
        wrapped.key_id().clone(), 8, wrapped.algorithm().clone(), wrapped.ciphertext().to_vec(),
    ).unwrap();
    assert_eq!(
        run_ready(provider.unwrap(&wrong_version, &context)),
        Err(KeyManagementError::KeyVersionUnavailable)
    );

    let wrong_algorithm = WrappedKey::new(
        wrapped.key_id().clone(),
        wrapped.key_version(),
        AlgorithmId::new("provider/unknown").unwrap(),
        wrapped.ciphertext().to_vec(),
    ).unwrap();
    assert_eq!(
        run_ready(provider.unwrap(&wrong_algorithm, &context)),
        Err(KeyManagementError::UnsupportedAlgorithm)
    );
}

#[test]
fn malformed_ciphertext_and_empty_plaintext_are_rejected() {
    let provider = TestProvider::new();
    let context = key_context(b"keys/application/primary");
    let key_id = KeyId::new("test/local-kek").unwrap();
    assert_eq!(
        run_ready(provider.wrap(&key_id, &[], &context)),
        Err(KeyManagementError::InvalidInput)
    );

    let malformed = WrappedKey::new(
        key_id, 7, AlgorithmId::new("AES-256-GCM").unwrap(), vec![0; 12],
    ).unwrap();
    assert_eq!(
        run_ready(provider.unwrap(&malformed, &context)),
        Err(KeyManagementError::InvalidWrappedKey)
    );
}

#[test]
fn tampered_wrapped_ciphertext_never_releases_plaintext() {
    let provider = TestProvider::new();
    let context = key_context(b"keys/application/primary");
    let wrapped = run_ready(provider.wrap(&provider.key_id, &[0x99; 32], &context)).unwrap();
    let mut ciphertext = wrapped.ciphertext().to_vec();
    *ciphertext.last_mut().unwrap() ^= 0x80;
    let tampered = WrappedKey::new(
        wrapped.key_id().clone(), wrapped.key_version(), wrapped.algorithm().clone(), ciphertext,
    ).unwrap();
    assert_eq!(
        run_ready(provider.unwrap(&tampered, &context)),
        Err(KeyManagementError::AuthenticationFailed)
    );
}


struct InjectedFailureProvider(KeyManagementError);

#[async_trait]
impl KeyManagementProvider for InjectedFailureProvider {
    async fn wrap(
        &self,
        _key_id: &KeyId,
        _plaintext: &[u8],
        _context: &KeyContext,
    ) -> Result<WrappedKey, KeyManagementError> {
        Err(self.0.clone())
    }

    async fn unwrap(
        &self,
        _wrapped: &WrappedKey,
        _context: &KeyContext,
    ) -> Result<Zeroizing<Vec<u8>>, KeyManagementError> {
        Err(self.0.clone())
    }
}

#[test]
fn provider_unavailability_and_internal_failures_are_injected_and_propagated() {
    let context = key_context(b"keys/application/primary");
    let key_id = KeyId::new("test/local-kek").unwrap();
    let wrapped = WrappedKey::new(
        key_id.clone(),
        7,
        AlgorithmId::new("AES-256-GCM").unwrap(),
        vec![0x01; 16],
    ).unwrap();

    for failure in [
        KeyManagementError::ProviderUnavailable,
        KeyManagementError::ProviderFailure,
    ] {
        let provider = InjectedFailureProvider(failure.clone());
        assert_eq!(
            run_ready(provider.wrap(&key_id, &[0x11; 32], &context)),
            Err(failure.clone())
        );
        assert_eq!(
            run_ready(provider.unwrap(&wrapped, &context)),
            Err(failure.clone())
        );
    }
}
