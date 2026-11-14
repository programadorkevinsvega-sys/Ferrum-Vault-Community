#!/usr/bin/env bash
set -Eeuo pipefail

: "${FERRUM_AWS_KMS_KEY_ARN:?Set FERRUM_AWS_KMS_KEY_ARN to a full customer-managed KMS key ARN}"
: "${FERRUM_AWS_KMS_RUNTIME_PRINCIPAL_ARN:?Set FERRUM_AWS_KMS_RUNTIME_PRINCIPAL_ARN to the IAM role or user ARN used by Ferrum}"

for command in aws cargo jq; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'ERROR: required command not found: %s\n' "$command" >&2
    exit 2
  }
done

KEY_ARN="$FERRUM_AWS_KMS_KEY_ARN"
if [[ ! "$KEY_ARN" =~ ^arn:(aws|aws-us-gov|aws-cn):kms:([a-z0-9-]+):[0-9]{12}:key/[^/:]+$ ]]; then
  echo "ERROR: FERRUM_AWS_KMS_KEY_ARN must be a full KMS key ARN (aliases are not accepted)." >&2
  exit 2
fi
REGION="${BASH_REMATCH[2]}"
KEY_ID="${KEY_ARN##*/}"
if [[ ! "$FERRUM_AWS_KMS_RUNTIME_PRINCIPAL_ARN" =~ ^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:(role|user)/.+$ ]]; then
  echo "ERROR: FERRUM_AWS_KMS_RUNTIME_PRINCIPAL_ARN must be an IAM role or user ARN." >&2
  exit 2
fi

if [[ -n "${AWS_REGION:-}" && "$AWS_REGION" != "$REGION" ]]; then
  printf 'ERROR: AWS_REGION (%s) does not match the key ARN region (%s).\n' "$AWS_REGION" "$REGION" >&2
  exit 2
fi
export AWS_REGION="$REGION"

# The SDK uses AWS_PROFILE or the standard credential chain. The audit CLI
# identity may be distinct, so key-policy and CloudTrail read access do not
# need to be added to the runtime role.
if [[ -n "${FERRUM_AWS_KMS_RUNTIME_PROFILE:-}" ]]; then
  export AWS_PROFILE="$FERRUM_AWS_KMS_RUNTIME_PROFILE"
fi
AUDIT_PROFILE_ARGS=()
if [[ -n "${FERRUM_AWS_KMS_AUDIT_PROFILE:-}" ]]; then
  AUDIT_PROFILE_ARGS=(--profile "$FERRUM_AWS_KMS_AUDIT_PROFILE")
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CALLER_ARN="$(aws "${AUDIT_PROFILE_ARGS[@]}" sts get-caller-identity \
  --region "$REGION" --query Arn --output text)"
printf 'Audit identity: %s\n' "$CALLER_ARN"
printf 'KMS key: %s\n' "$KEY_ARN"
printf 'Region: %s\n' "$REGION"

# Read the actual resource key policy. This requires kms:GetKeyPolicy for the
# audit identity; the application runtime role does not need this permission.
aws "${AUDIT_PROFILE_ARGS[@]}" kms get-key-policy \
  --key-id "$KEY_ARN" --policy-name default --region "$REGION" \
  --query Policy --output text >"$TMP_DIR/key-policy.json"
ACCOUNT_ID="$(printf '%s' "$KEY_ARN" | cut -d: -f5)"
PARTITION="$(printf '%s' "$KEY_ARN" | cut -d: -f2)"
ACCOUNT_ROOT_ARN="arn:${PARTITION}:iam::${ACCOUNT_ID}:root"
jq -e --arg principal "$FERRUM_AWS_KMS_RUNTIME_PRINCIPAL_ARN" --arg root "$ACCOUNT_ROOT_ARN" '
  def listify: if type == "array" then . else [.] end;
  .Version and (.Statement | type == "array")
  and any(.Statement[]?;
    .Effect == "Allow"
    and ((.Principal.AWS // null) | listify | any(. == $principal or . == $root))
  )
' "$TMP_DIR/key-policy.json" >/dev/null
echo "KMS key policy: retrieved; it delegates to the configured runtime principal or account root."

# Check key type, usage, state, and exact ARN before sending test ciphertext.
aws "${AUDIT_PROFILE_ARGS[@]}" kms describe-key \
  --key-id "$KEY_ARN" --region "$REGION" >"$TMP_DIR/describe-key.json"
jq -e --arg arn "$KEY_ARN" '
  .KeyMetadata
  | .Arn == $arn
    and .KeySpec == "SYMMETRIC_DEFAULT"
    and .KeyUsage == "ENCRYPT_DECRYPT"
    and .KeyState == "Enabled"
' "$TMP_DIR/describe-key.json" >/dev/null
echo "KMS key metadata: enabled SYMMETRIC_DEFAULT / ENCRYPT_DECRYPT."

# The Rust example invokes the official SDK, not the AWS CLI. It generates
# fresh synthetic 32-byte plaintext and a random ceremony id. It emits only
# public metadata and the SHA-256 encryption-context fingerprint.
if ! cargo run --locked --manifest-path crates/seal/Cargo.toml \
  --features aws-kms --example aws_kms_live_verify \
  >"$TMP_DIR/sdk-output.txt" 2>"$TMP_DIR/sdk-stderr.txt"; then
  echo "ERROR: official AWS SDK Encrypt/Decrypt verification failed." >&2
  tail -n 30 "$TMP_DIR/sdk-stderr.txt" >&2
  exit 1
fi
cat "$TMP_DIR/sdk-output.txt"

CONTEXT_DIGEST="$(sed -n 's/^FERRUM_KMS_CONTEXT_SHA256=//p' "$TMP_DIR/sdk-output.txt")"
RESULT="$(sed -n 's/^FERRUM_KMS_RESULT=//p' "$TMP_DIR/sdk-output.txt")"
if [[ "$RESULT" != "success" || ! "$CONTEXT_DIGEST" =~ ^[0-9a-f]{64}$ ]]; then
  echo "ERROR: the SDK verifier did not emit a successful result and context digest." >&2
  exit 1
fi

aws "${AUDIT_PROFILE_ARGS[@]}" iam simulate-principal-policy \
  --policy-source-arn "$FERRUM_AWS_KMS_RUNTIME_PRINCIPAL_ARN" \
  --action-names kms:DescribeKey kms:Encrypt kms:Decrypt \
  --resource-arns "$KEY_ARN" \
  --context-entries \
    "ContextKeyName=kms:EncryptionContext:FerrumContextSHA256V1,ContextKeyValues=$CONTEXT_DIGEST,ContextKeyType=string" \
    "ContextKeyName=kms:EncryptionContextKeys,ContextKeyValues=FerrumContextSHA256V1,ContextKeyType=stringList" \
  >"$TMP_DIR/iam-simulation.json"
jq -e '
  (.EvaluationResults | length) == 3
  and all(.EvaluationResults[]; .EvalDecision == "allowed")
' "$TMP_DIR/iam-simulation.json" >/dev/null
echo "IAM policy simulation: DescribeKey, Encrypt and Decrypt allowed for the exact runtime principal and context."

# CloudTrail Event History is regional and eventually consistent. Search each
# event independently and require the exact context hash and key identifier.
if date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ >/dev/null 2>&1; then
  START_TIME="$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ)"
else
  START_TIME="$(date -u -v-15M +%Y-%m-%dT%H:%M:%SZ)"
fi

verify_cloudtrail_event() {
  local event_name="$1"
  local attempt
  local events_file="$TMP_DIR/cloudtrail-$event_name.json"

  for attempt in $(seq 1 18); do
    aws "${AUDIT_PROFILE_ARGS[@]}" cloudtrail lookup-events \
      --lookup-attributes "AttributeKey=EventName,AttributeValue=$event_name" \
      --start-time "$START_TIME" \
      --region "$REGION" \
      --max-results 50 >"$events_file"

    if jq -e --arg event "$event_name" \
      --arg digest "$CONTEXT_DIGEST" \
      --arg arn "$KEY_ARN" \
      --arg keyid "$KEY_ID" '
      any(.Events[]?;
        (try (.CloudTrailEvent | fromjson) catch {}) as $record
        | ($record.eventSource // "") == "kms.amazonaws.com"
          and ($record.eventName // "") == $event
          and ($record.requestParameters.encryptionContext.FerrumContextSHA256V1 // "") == $digest
          and (
            ($record.requestParameters.keyId // "") == $arn
            or ($record.requestParameters.keyId // "") == $keyid
            or (($record.requestParameters.keyId // "") | endswith($keyid))
            or any($record.resources[]?; ((.ARN // "") == $arn or ((.ARN // "") | endswith($keyid))))
          )
      )
    ' "$events_file" >/dev/null; then
      printf 'CloudTrail: verified %s with matching key ARN and context fingerprint.\n' "$event_name"
      return 0
    fi

    sleep 10
  done

  printf 'ERROR: CloudTrail Event History did not return matching %s within 3 minutes.\n' "$event_name" >&2
  echo "Check the KMS Region, CloudTrail Event History, request context and audit identity." >&2
  return 1
}

verify_cloudtrail_event Encrypt
verify_cloudtrail_event Decrypt

echo "AWS KMS integration verification: PASS"
echo "Verified: key policy delegation, IAM policy simulation, DescribeKey, Encrypt, Decrypt, and matching CloudTrail Event History entries."
echo "The encrypted/decrypted plaintext was synthetic and existed only in this process."
