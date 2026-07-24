#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{
    Clock, ClockError, DeviceEnrollmentChallengeId, DeviceId, DeviceSessionChallengeId,
    DeviceSessionId, IdentityId,
};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_node::{
    DEVICE_ENROLLMENT_CANDIDATE_CONTENT_TYPE, DEVICE_ENROLLMENT_CHALLENGE_PATH,
    DEVICE_ENROLLMENT_CONTENT_TYPE, DEVICE_ENROLLMENT_PATH, DEVICE_REVOKE_PATH_TEMPLATE,
    DEVICE_SESSION_AUTHORIZATION_SCHEME, DEVICE_SESSION_CHALLENGE_PATH, DEVICE_SESSION_PATH,
    DEVICE_SESSION_RECEIPT_CONTENT_TYPE, HISTORY_RECOVERY_REQUEST_CONTENT_TYPE,
    IDENTITY_APPEND_RECEIPT_CONTENT_TYPE, IDENTITY_BOOTSTRAP_PATH, IDENTITY_LOG_EVENT_CONTENT_TYPE,
    INITIAL_DEVICE_ENROLL_PATH, IdentityBootstrapState, identity_bootstrap_router_with_state,
    parse_device_session_authorization,
};
use dtx_identity_persistence::{
    DEVICE_ENROLLMENT_CAPABILITY_HASH_DOMAIN, DEVICE_SESSION_SECRET_HASH_DOMAIN,
    DeviceSessionCompletionCommand, DeviceSessionCredential, DeviceSessionRepository,
    HISTORY_RECOVERY_REQUEST_HASH_DOMAIN, IdentityAppendCommand, IdentityAppendOutcome,
    IdentityLogHead, IdentityLogRepository, IdentityPgStore, device_session_proof_input,
    history_recovery_request_signature_input, history_recovery_request_unsigned_canonical_bytes,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;

const BOOTSTRAP_KEY: &str = "bootstrap-device-session-0001";
const INITIAL_DEVICE_KEY: &str = "initial-device-session-0001";
const SESSION_KEY: &str = "device-session-command-0001";
const SESSION_RETRY_KEY: &str = "device-session-command-0002";
const EXPIRED_SESSION_KEY: &str = "device-session-command-0003";
const AUDIENCE: &str = "https://identity.test";

type StoredHistoryRecoveryRequest = (i16, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);

#[allow(clippy::too_many_arguments)]
fn history_recovery_request_body(
    candidate: &SigningKey,
    request_id: DeviceEnrollmentChallengeId,
    identity_id: IdentityId,
    candidate_device_id: DeviceId,
    recipient_encryption_key: DeviceEncryptionPublicKey,
    observed_head: IdentityLogHead,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    capability: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let unsigned = history_recovery_request_unsigned_canonical_bytes(
        request_id,
        identity_id,
        candidate_device_id,
        public_key(candidate)?,
        recipient_encryption_key,
        observed_head,
        issued_at,
        expires_at,
    )?;
    let candidate_signature = signature(
        candidate,
        &history_recovery_request_signature_input(&unsigned),
    );
    let CanonicalValue::Map(mut fields) = decode_deterministic_cbor(&unsigned)? else {
        return Err("unsigned history recovery request is not a map".into());
    };
    fields.push((
        CanonicalValue::Unsigned(12),
        candidate_signature.to_canonical_value(),
    ));
    let exact_signed_request = encode_deterministic_cbor(&CanonicalValue::Map(fields.clone()))?;
    fields.push((
        CanonicalValue::Unsigned(13),
        CanonicalValue::Bytes(capability.to_vec()),
    ));
    Ok((
        encode_deterministic_cbor(&CanonicalValue::Map(fields))?,
        exact_signed_request,
    ))
}

async fn send_device_enrollment_challenge(
    app: axum::Router,
    idempotency_key: &str,
    content_type: &str,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(DEVICE_ENROLLMENT_CHALLENGE_PATH)
            .header(header::CONTENT_TYPE, content_type)
            .header("idempotency-key", idempotency_key)
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_device_enrollment_approval(
    app: axum::Router,
    idempotency_key: &str,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
    expected_head_hash: Sha256Digest,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(DEVICE_ENROLLMENT_PATH)
            .header(header::CONTENT_TYPE, DEVICE_ENROLLMENT_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(header::IF_MATCH, format!("\"{expected_head_hash}\""))
            .header(
                header::AUTHORIZATION,
                format!(
                    "{DEVICE_SESSION_AUTHORIZATION_SCHEME} {session_id}.{}",
                    Base64UrlUnpadded::encode_string(&session_secret)
                ),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
async fn send_device_revoke(
    app: axum::Router,
    idempotency_key: &str,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
    identity_id: IdentityId,
    target_device_id: DeviceId,
    expected_head_hash: Sha256Digest,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    let path = DEVICE_REVOKE_PATH_TEMPLATE
        .replace("{identity_id}", &identity_id.to_string())
        .replace("{device_id}", &target_device_id.to_string());
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, IDENTITY_LOG_EVENT_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(header::IF_MATCH, format!("\"{expected_head_hash}\""))
            .header(
                header::AUTHORIZATION,
                format!(
                    "{DEVICE_SESSION_AUTHORIZATION_SCHEME} {session_id}.{}",
                    Base64UrlUnpadded::encode_string(&session_secret)
                ),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

fn enrollment_challenge_id(bytes: &[u8]) -> Result<DeviceEnrollmentChallengeId, Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("device enrollment challenge response must be a CBOR map".into());
    };
    let challenge_id = fields
        .iter()
        .find_map(|(key, value)| (key == &CanonicalValue::Unsigned(2)).then_some(value))
        .ok_or("device enrollment challenge ID field missing")?;
    let CanonicalValue::Text(challenge_id) = challenge_id else {
        return Err("device enrollment challenge ID must be text".into());
    };
    Ok(challenge_id.parse()?)
}

async fn send_event(
    app: axum::Router,
    path: &str,
    idempotency_key: &str,
    expected_genesis_hash: Option<Sha256Digest>,
    bytes: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, IDENTITY_LOG_EVENT_CONTENT_TYPE)
        .header("idempotency-key", idempotency_key);
    if let Some(expected_genesis_hash) = expected_genesis_hash {
        request = request.header(header::IF_MATCH, format!("\"{expected_genesis_hash}\""));
    }
    app.oneshot(request.body(Body::from(bytes))?)
        .await
        .map_err(Into::into)
}

async fn send_session(
    app: axum::Router,
    idempotency_key: &str,
    body: serde_json::Value,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(DEVICE_SESSION_PATH)
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", idempotency_key)
            .body(Body::from(serde_json::to_vec(&body)?))?,
    )
    .await
    .map_err(Into::into)
}

async fn assert_safe_error(
    response: axum::response::Response,
    expected_code: &str,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    let body = to_bytes(response.into_body(), 16_384).await?;
    let body: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_str),
        Some(expected_code)
    );
    assert!(body.get("session_secret").is_none());
    Ok(())
}

async fn assert_identity_entry_count(
    pool: &PgPool,
    identity_id: IdentityId,
    expected: i64,
) -> Result<(), Box<dyn Error>> {
    let actual: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.log_entries WHERE identity_id=$1")
            .bind(identity_id.to_string())
            .fetch_one(pool)
            .await?;
    assert_eq!(actual, expected);
    Ok(())
}

async fn assert_challenge_stores_only_hash(
    pool: &PgPool,
    challenge_id: DeviceSessionChallengeId,
    nonce: [u8; 32],
) -> Result<(), Box<dyn Error>> {
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT nonce_hash FROM identity.device_session_challenges WHERE challenge_id=$1",
    )
    .bind(*challenge_id.as_uuid())
    .fetch_one(pool)
    .await?;
    assert_eq!(stored.len(), 32);
    assert_ne!(stored, nonce);
    Ok(())
}

async fn assert_session_count(pool: &PgPool, expected: i64) -> Result<(), Box<dyn Error>> {
    let actual: i64 = sqlx::query_scalar("SELECT count(*) FROM identity.device_sessions")
        .fetch_one(pool)
        .await?;
    assert_eq!(actual, expected);
    Ok(())
}

async fn assert_device_session_state_counts(
    pool: &PgPool,
    expected: (i64, i64, i64, i64),
) -> Result<(), Box<dyn Error>> {
    let actual: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
             (SELECT count(*) FROM identity.device_session_challenges),
             (SELECT count(*) FROM identity.device_sessions),
             (SELECT count(*) FROM identity.device_session_idempotency_claims),
             (SELECT count(*) FROM identity.device_session_receipts)",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(actual, expected);
    Ok(())
}

fn decode_32(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let mut bytes = [0_u8; 32];
    let decoded = Base64UrlUnpadded::decode(value, &mut bytes)?;
    if decoded.len() != bytes.len() {
        return Err("expected 32-byte base64url value".into());
    }
    Ok(bytes)
}

fn genesis(
    root: &SigningKey,
    recovery: &SigningKey,
    occurred_at: i64,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let root_key = public_key(root)?;
    let recovery_key = public_key(recovery)?;
    let identity_id = IdentityId::derive(root_key.as_domain_key());
    let recovery_acceptance_signature = signature(
        recovery,
        &genesis_recovery_acceptance_input(identity_id, root_key, recovery_key)?,
    );
    signed_event(
        root,
        identity_id,
        1,
        None,
        occurred_at,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature,
        },
    )
}

fn device_add(
    root: &SigningKey,
    device: &SigningKey,
    identity_id: IdentityId,
    device_id: DeviceId,
    previous_hash: Sha256Digest,
    sequence: u64,
    occurred_at: i64,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    device_add_with_encryption(
        root,
        device,
        &DeviceAddInput {
            identity_id,
            device_id,
            previous_hash,
            sequence,
            occurred_at,
            encryption_key: [7_u8; 32],
        },
    )
}

struct DeviceAddInput {
    identity_id: IdentityId,
    device_id: DeviceId,
    previous_hash: Sha256Digest,
    sequence: u64,
    occurred_at: i64,
    encryption_key: [u8; 32],
}

fn device_add_with_encryption(
    root: &SigningKey,
    device: &SigningKey,
    input: &DeviceAddInput,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let root_key = public_key(root)?;
    let device_key = public_key(device)?;
    let encryption_key = DeviceEncryptionPublicKey::try_from(input.encryption_key)?;
    let certificate_unsigned = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        input.identity_id,
        input.device_id,
        device_key,
        encryption_key,
        root_key,
        UtcMillis::new(input.occurred_at - 1)?,
    )?;
    let certificate = DeviceCertificateV1::signed(
        certificate_unsigned.clone(),
        signature(
            root,
            &device_certificate_signature_input(certificate_unsigned.signing_digest()?),
        ),
    )?;
    signed_event(
        root,
        input.identity_id,
        input.sequence,
        Some(input.previous_hash),
        input.occurred_at,
        IdentityLogEventPayloadV1::DeviceAdd { certificate },
    )
}

fn signed_event(
    signer: &SigningKey,
    identity_id: IdentityId,
    sequence: u64,
    previous_hash: Option<Sha256Digest>,
    occurred_at: i64,
    payload: IdentityLogEventPayloadV1,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let signer_key = public_key(signer)?;
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        SafeUint::new(sequence)?,
        previous_hash,
        UtcMillis::new(occurred_at)?,
        payload,
        signer_key,
    )?;
    Ok(IdentityLogEventV1::signed(
        unsigned.clone(),
        signature(
            signer,
            &identity_log_signature_input(unsigned.signing_digest()?),
        ),
    )?)
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public_key(key: &SigningKey) -> Result<SigningPublicKey, Box<dyn Error>> {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).map_err(Into::into)
}

fn signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now_utc_millis(&self) -> Result<i64, ClockError> {
        Ok(self.0)
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    include!("fixtures/device_sessions_bootstrap.inc.rs");
    include!("fixtures/device_sessions_recovery.inc.rs");
    include!("fixtures/device_sessions_enrollment.inc.rs");
    include!("fixtures/device_sessions_revoke.inc.rs");
}
