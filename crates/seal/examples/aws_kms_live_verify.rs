//! Live AWS KMS SDK integration verification.
//!
//! Uses a fresh synthetic 256-bit root, never a production root or recovery
//! share. The program prints the public context fingerprint for CloudTrail
//! correlation, but never prints plaintext or ciphertext.

use std::env;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use ferrum_seal::aws_kms::{AwsKmsUnsealer, AwsSdkKmsApi, kms_context_sha256_hex};
use ferrum_seal::unsealer::{UnsealRequest, Unsealer};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_arn = env::var("FERRUM_AWS_KMS_KEY_ARN")
        .map_err(|_| "FERRUM_AWS_KMS_KEY_ARN must contain a full KMS key ARN")?;
    let key_version = env::var("FERRUM_AWS_KMS_ENVELOPE_VERSION")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(1);
    if key_version == 0 {
        return Err("FERRUM_AWS_KMS_ENVELOPE_VERSION must be positive".into());
    }

    let adapter = AwsKmsUnsealer::<AwsSdkKmsApi>::from_environment(key_arn, key_version).await?;
    let mut synthetic_root = Zeroizing::new(vec![0_u8; 32]);
    SystemRandom::new().fill(&mut synthetic_root)?;
    let mut ceremony_id = [0_u8; 16];
    SystemRandom::new().fill(&mut ceremony_id)?;

    let context_digest = kms_context_sha256_hex(ceremony_id);
    let wrapped = adapter
        .encrypt_root_for_unseal(synthetic_root.as_slice(), ceremony_id)
        .await?;
    let recovered = adapter
        .unseal(UnsealRequest::from_wrapped(ceremony_id, &wrapped))
        .await?;

    if recovered.as_slice() != synthetic_root.as_slice() {
        return Err("KMS round-trip plaintext did not match synthetic test material".into());
    }

    println!("FERRUM_KMS_RESULT=success");
    println!("FERRUM_KMS_REGION={}", adapter.region());
    println!("FERRUM_KMS_KEY_ARN={}", adapter.configured_key_arn());
    println!("FERRUM_KMS_CONTEXT_SHA256={context_digest}");
    println!("FERRUM_KMS_ENVELOPE_VERSION={}", wrapped.key_version());

    drop(recovered);
    drop(synthetic_root);
    Ok(())
}
