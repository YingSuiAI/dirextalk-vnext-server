#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{
    error::Error,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{
    Clock, ClockError, DeviceEnrollmentChallengeId, DeviceId, DeviceSessionId, IdentityId,
};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_node::{
    DEVICE_ENROLLMENT_CAPABILITY_HEADER, DEVICE_ENROLLMENT_CHALLENGE_STATUS_PATH,
    DEVICE_SESSION_AUTHORIZATION_SCHEME, HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE,
    HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE, HISTORY_RECOVERY_REQUEST_V4_PATH,
    IdentityBootstrapState, RECOVERY_RESPONSE_CAPABILITY_HEADER,
    RECOVERY_SCOPE_CATALOG_CONTENT_TYPE, RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_PATH_TEMPLATE, RECOVERY_SCOPE_CATALOG_PREPARATION_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_PREPARATION_PATH_TEMPLATE,
    RECOVERY_SCOPE_CATALOG_PREPARATION_RECEIPT_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_PREPARATIONS_PATH,
    RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_PATH_TEMPLATE,
    RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE,
    RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE, identity_bootstrap_router_with_state,
};
use dtx_identity_persistence::{
    CATALOG_CIPHERTEXT_HASH_DOMAIN, CATALOG_HEAD_SIGNATURE_DOMAIN,
    CreateDeviceEnrollmentChallengeCommand, DEVICE_SESSION_SECRET_HASH_DOMAIN,
    DeviceEnrollmentApprovalCommand, DeviceEnrollmentCapability, DeviceEnrollmentChallengeOutcome,
    DeviceEnrollmentRepository, DeviceSessionCompletionCommand, DeviceSessionCredential,
    DeviceSessionOutcome, DeviceSessionRepository, HISTORY_RECOVERY_REQUEST_V4_SIGNATURE_DOMAIN,
    IdentityAppendCommand, IdentityAppendOutcome, IdentityLogHead, IdentityLogRepository,
    IdentityPgStore, MAX_RECOVERY_SCOPE_CATALOG_PREPARATION_BYTES,
    MAX_RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_BYTES, MAX_RECOVERY_SCOPE_CATALOG_UPLOAD_BYTES,
    PREPARATION_DIGEST_DOMAIN, PREPARATION_SIGNATURE_DOMAIN, PROVIDER_AAD_DIGEST_DOMAIN,
    PROVIDER_AUTHORITY_SIGNATURE_DOMAIN, PROVIDER_CIPHERTEXT_HASH_DOMAIN,
    PROVIDER_PACKAGE_DIGEST_DOMAIN, PROVIDER_RESPONSE_SIGNATURE_DOMAIN, RECIPIENT_KEY_HASH_DOMAIN,
    RESPONSE_CAPABILITY_HASH_DOMAIN, device_session_proof_input,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use tower::ServiceExt;

const AUDIENCE: &str = "https://identity.test";
const AUTHORITY_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a3";
const PROVIDER_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a4";
const CANDIDATE_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a5";
const SECOND_CANDIDATE_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a6";

#[derive(Clone, Copy)]
struct Session {
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
}

async fn session(
    store: &IdentityPgStore,
    identity: IdentityId,
    device: DeviceId,
    signing: &SigningKey,
    seed: u8,
    now: UtcMillis,
) -> Result<Session, Box<dyn Error>> {
    let challenge = DeviceSessionRepository
        .issue_challenge(store, identity, device, [seed; 32], AUDIENCE, now)
        .await?;
    let session_id = DeviceSessionId::new();
    let session_secret = [seed.wrapping_add(1); 32];
    let secret_hash = Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let proof = signature(
        signing,
        &device_session_proof_input(
            identity,
            device,
            challenge.challenge_id(),
            challenge.nonce(),
            AUDIENCE,
            session_id,
            secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    let command = DeviceSessionCompletionCommand::new(
        Sha256Digest::from_bytes([seed.wrapping_add(2); 32]),
        identity,
        device,
        challenge.challenge_id(),
        session_id,
        *challenge.nonce(),
        session_secret,
        proof,
    )?;
    assert!(matches!(
        DeviceSessionRepository
            .complete(store, &command, at(now.get() + 1))
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(Session {
        session_id,
        session_secret,
    })
}

async fn send_catalog(
    app: axum::Router,
    idempotency: &str,
    session: &Session,
    generation: u64,
    content_type: &str,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    send_catalog_custom(
        app,
        idempotency,
        session,
        generation,
        content_type,
        Some(RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE),
        None,
        body,
    )
    .await
}

async fn send_catalog_custom(
    app: axum::Router,
    idempotency: &str,
    session: &Session,
    generation: u64,
    content_type: &str,
    accept: Option<&str>,
    declared_length: Option<&str>,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    let mut builder = Request::builder()
        .method("PUT")
        .uri(
            RECOVERY_SCOPE_CATALOG_PATH_TEMPLATE
                .replace(
                    "{catalog_id}",
                    if generation == 1 {
                        "0190f2a5-7b1c-7abc-8def-0123456789b1"
                    } else {
                        "0190f2a5-7b1c-7abc-8def-0123456789b3"
                    },
                )
                .replace("{generation}", &generation.to_string()),
        )
        .header(header::CONTENT_TYPE, content_type)
        .header("idempotency-key", idempotency)
        .header(header::AUTHORIZATION, authorization(session));
    if let Some(accept) = accept {
        builder = builder.header(header::ACCEPT, accept);
    }
    if let Some(length) = declared_length {
        builder = builder.header(header::CONTENT_LENGTH, length);
    }
    Ok(app.oneshot(builder.body(Body::from(body))?).await?)
}

async fn send_preparation(
    app: axum::Router,
    idempotency: &str,
    enrollment_capability: [u8; 32],
    response_capability: [u8; 32],
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    send_preparation_custom(
        app,
        idempotency,
        enrollment_capability,
        response_capability,
        RECOVERY_SCOPE_CATALOG_PREPARATION_CONTENT_TYPE,
        Some(RECOVERY_SCOPE_CATALOG_PREPARATION_RECEIPT_CONTENT_TYPE),
        None,
        body,
    )
    .await
}

async fn send_preparation_custom(
    app: axum::Router,
    idempotency: &str,
    enrollment_capability: [u8; 32],
    response_capability: [u8; 32],
    content_type: &str,
    accept: Option<&str>,
    declared_length: Option<&str>,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(RECOVERY_SCOPE_CATALOG_PREPARATIONS_PATH)
        .header(header::CONTENT_TYPE, content_type)
        .header("idempotency-key", idempotency)
        .header(
            DEVICE_ENROLLMENT_CAPABILITY_HEADER,
            Base64UrlUnpadded::encode_string(&enrollment_capability),
        )
        .header(
            RECOVERY_RESPONSE_CAPABILITY_HEADER,
            Base64UrlUnpadded::encode_string(&response_capability),
        );
    if let Some(accept) = accept {
        builder = builder.header(header::ACCEPT, accept);
    }
    if let Some(length) = declared_length {
        builder = builder.header(header::CONTENT_LENGTH, length);
    }
    Ok(app.oneshot(builder.body(Body::from(body))?).await?)
}

async fn send_status(
    app: axum::Router,
    request_id: dtx_domain::DeviceEnrollmentChallengeId,
    response_capability: [u8; 32],
) -> Result<axum::response::Response, Box<dyn Error>> {
    send_status_custom(
        app,
        request_id,
        response_capability,
        None,
        Some(RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE),
        Vec::new(),
    )
    .await
}

async fn send_status_custom(
    app: axum::Router,
    request_id: dtx_domain::DeviceEnrollmentChallengeId,
    response_capability: [u8; 32],
    content_type: Option<&str>,
    accept: Option<&str>,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(
            RECOVERY_SCOPE_CATALOG_PREPARATION_PATH_TEMPLATE
                .replace("{request_id}", &request_id.to_string()),
        )
        .header(
            RECOVERY_RESPONSE_CAPABILITY_HEADER,
            Base64UrlUnpadded::encode_string(&response_capability),
        );
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(accept) = accept {
        builder = builder.header(header::ACCEPT, accept);
    }
    Ok(app.oneshot(builder.body(Body::from(body))?).await?)
}

async fn send_provider_response(
    app: axum::Router,
    idempotency: &str,
    session: &Session,
    request_id: dtx_domain::DeviceEnrollmentChallengeId,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    send_provider_response_custom(
        app,
        idempotency,
        session,
        request_id,
        RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
        Some(RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE),
        None,
        body,
    )
    .await
}

async fn send_provider_response_custom(
    app: axum::Router,
    idempotency: &str,
    session: &Session,
    request_id: dtx_domain::DeviceEnrollmentChallengeId,
    content_type: &str,
    accept: Option<&str>,
    declared_length: Option<&str>,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    let mut builder = Request::builder()
        .method("PUT")
        .uri(
            RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_PATH_TEMPLATE
                .replace("{request_id}", &request_id.to_string()),
        )
        .header(header::CONTENT_TYPE, content_type)
        .header("idempotency-key", idempotency)
        .header(header::AUTHORIZATION, authorization(session));
    if let Some(accept) = accept {
        builder = builder.header(header::ACCEPT, accept);
    }
    if let Some(length) = declared_length {
        builder = builder.header(header::CONTENT_LENGTH, length);
    }
    Ok(app.oneshot(builder.body(Body::from(body))?).await?)
}

async fn send_history_recovery_request_v4(
    app: axum::Router,
    idempotency: &str,
    enrollment_capability: [u8; 32],
    response_capability: [u8; 32],
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    Ok(app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(HISTORY_RECOVERY_REQUEST_V4_PATH)
                .header(
                    header::CONTENT_TYPE,
                    HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE,
                )
                .header(
                    header::ACCEPT,
                    HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE,
                )
                .header("idempotency-key", idempotency)
                .header(
                    DEVICE_ENROLLMENT_CAPABILITY_HEADER,
                    Base64UrlUnpadded::encode_string(&enrollment_capability),
                )
                .header(
                    RECOVERY_RESPONSE_CAPABILITY_HEADER,
                    Base64UrlUnpadded::encode_string(&response_capability),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

async fn cancel_enrollment_challenge(
    app: axum::Router,
    challenge_id: DeviceEnrollmentChallengeId,
    capability: [u8; 32],
) -> Result<axum::response::Response, Box<dyn Error>> {
    Ok(app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(
                    DEVICE_ENROLLMENT_CHALLENGE_STATUS_PATH
                        .replace("{challenge_id}", &challenge_id.to_string()),
                )
                .header(
                    DEVICE_ENROLLMENT_CAPABILITY_HEADER,
                    Base64UrlUnpadded::encode_string(&capability),
                )
                .body(Body::empty())?,
        )
        .await?)
}

#[allow(clippy::too_many_arguments)]
fn history_recovery_request_v4_body(
    request_id: DeviceEnrollmentChallengeId,
    identity: IdentityId,
    candidate_device: DeviceId,
    candidate: &SigningKey,
    recipient: [u8; 32],
    pre_head: IdentityLogHead,
    post_head: IdentityLogHead,
    device_add: &[u8],
    preparation: &[u8],
    catalog_id: uuid::Uuid,
    catalog_head: &[u8],
    catalog_head_digest: Sha256Digest,
    response_capability: [u8; 32],
    idempotency: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let leaves = CanonicalValue::Array(vec![CanonicalValue::Bytes(vec![0x91; 32])]);
    let leaf_bytes = encode_deterministic_cbor(&leaves)?;
    let manifest = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(identity.to_string())),
        field(3, CanonicalValue::Text(catalog_id.to_string())),
        field(4, safe(1).to_canonical_value()),
        field(5, CanonicalValue::Bytes(catalog_head.to_vec())),
        field(6, catalog_head_digest.to_canonical_value()),
        field(7, Sha256Digest::from_bytes([31; 32]).to_canonical_value()),
        field(8, CanonicalValue::Unsigned(1)),
        field(
            9,
            Sha256Digest::hash_domain(b"dirextalk.history-recovery.leaf-set.v2\0", &leaf_bytes)
                .to_canonical_value(),
        ),
        field(10, leaves),
    ]);
    let manifest_bytes = encode_deterministic_cbor(&manifest)?;
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(4)),
        field(2, CanonicalValue::Text(request_id.to_string())),
        field(3, CanonicalValue::Text(identity.to_string())),
        field(4, CanonicalValue::Text(candidate_device.to_string())),
        field(5, public(candidate).to_canonical_value()),
        field(6, CanonicalValue::Bytes(recipient.to_vec())),
        field(7, pre_head.sequence().to_canonical_value()),
        field(8, pre_head.hash().to_canonical_value()),
        field(9, post_head.sequence().to_canonical_value()),
        field(10, post_head.hash().to_canonical_value()),
        field(11, CanonicalValue::Bytes(device_add.to_vec())),
        field(
            12,
            Sha256Digest::hash_domain(b"dirextalk.identity-device-add.v1\0", device_add)
                .to_canonical_value(),
        ),
        field(13, CanonicalValue::Bytes(preparation.to_vec())),
        field(
            14,
            Sha256Digest::hash_domain(PREPARATION_DIGEST_DOMAIN, preparation).to_canonical_value(),
        ),
        field(15, manifest),
        field(
            16,
            Sha256Digest::hash_domain(b"dirextalk.history-recovery.manifest.v2\0", &manifest_bytes)
                .to_canonical_value(),
        ),
        field(17, at(5_300).to_canonical_value()),
        // Provider authorization is valid through 200_000, so the request
        // interval must contain that full accepted provider interval.
        field(18, at(200_000).to_canonical_value()),
        field(
            19,
            Sha256Digest::hash_domain(RESPONSE_CAPABILITY_HASH_DOMAIN, &response_capability)
                .to_canonical_value(),
        ),
        field(
            20,
            Sha256Digest::hash_domain(
                b"dirextalk.history-recovery.request-idempotency.v4\0",
                idempotency.as_bytes(),
            )
            .to_canonical_value(),
        ),
    ]);
    let unsigned_bytes = encode_deterministic_cbor(&unsigned)?;
    let mut input = HISTORY_RECOVERY_REQUEST_V4_SIGNATURE_DOMAIN.to_vec();
    input.extend_from_slice(&unsigned_bytes);
    let CanonicalValue::Map(mut fields) = unsigned else {
        unreachable!()
    };
    fields.push(field(21, signature(candidate, &input).to_canonical_value()));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(fields))?)
}

fn resign_history_recovery_request_v4(
    value: CanonicalValue,
    candidate: &SigningKey,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let CanonicalValue::Map(mut fields) = value else {
        return Err("V4 request must be a map".into());
    };
    if fields.len() != 21 {
        return Err("V4 request field count changed".into());
    }
    fields.truncate(20);
    let unsigned = encode_deterministic_cbor(&CanonicalValue::Map(fields.clone()))?;
    let mut input = HISTORY_RECOVERY_REQUEST_V4_SIGNATURE_DOMAIN.to_vec();
    input.extend_from_slice(&unsigned);
    fields.push(field(21, signature(candidate, &input).to_canonical_value()));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(fields))?)
}

fn history_recovery_request_v4_with_manifest_tamper(
    bytes: &[u8],
    candidate: &SigningKey,
    field_index: usize,
    replacement: CanonicalValue,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let CanonicalValue::Map(mut fields) = decode_deterministic_cbor(bytes)? else {
        return Err("V4 request must be a map".into());
    };
    let CanonicalValue::Map(mut manifest) = fields[14].1.clone() else {
        return Err("V4 manifest must be a map".into());
    };
    manifest[field_index - 1].1 = replacement;
    let manifest_value = CanonicalValue::Map(manifest);
    let manifest_bytes = encode_deterministic_cbor(&manifest_value)?;
    fields[14].1 = manifest_value;
    fields[15].1 =
        Sha256Digest::hash_domain(b"dirextalk.history-recovery.manifest.v2\0", &manifest_bytes)
            .to_canonical_value();
    resign_history_recovery_request_v4(CanonicalValue::Map(fields), candidate)
}

fn history_recovery_request_v4_with_outer_tamper(
    bytes: &[u8],
    candidate: &SigningKey,
    field_index: usize,
    replacement: CanonicalValue,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let CanonicalValue::Map(mut fields) = decode_deterministic_cbor(bytes)? else {
        return Err("V4 request must be a map".into());
    };
    fields[field_index - 1].1 = replacement;
    resign_history_recovery_request_v4(CanonicalValue::Map(fields), candidate)
}

fn history_recovery_request_v4_with_payload_tamper(
    bytes: &[u8],
    candidate: &SigningKey,
    field_index: usize,
    payload: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let CanonicalValue::Map(mut fields) = decode_deterministic_cbor(bytes)? else {
        return Err("V4 request must be a map".into());
    };
    fields[field_index - 1].1 = CanonicalValue::Bytes(payload.clone());
    let (digest_field, digest_domain): (usize, &[u8]) = match field_index {
        11 => (12, b"dirextalk.identity-device-add.v1\0"),
        13 => (
            14,
            b"dirextalk.recovery-scope-catalog-handoff-preparation-digest.v2\0",
        ),
        _ => return Err("unsupported V4 payload field".into()),
    };
    fields[digest_field - 1].1 =
        Sha256Digest::hash_domain(digest_domain, &payload).to_canonical_value();
    resign_history_recovery_request_v4(CanonicalValue::Map(fields), candidate)
}

fn history_recovery_request_v4_with_signature_tamper(
    bytes: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let CanonicalValue::Map(mut fields) = decode_deterministic_cbor(bytes)? else {
        return Err("V4 request must be a map".into());
    };
    fields[20].1 = CanonicalValue::Bytes(vec![0; 64]);
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(fields))?)
}

fn authorization(session: &Session) -> String {
    format!(
        "{DEVICE_SESSION_AUTHORIZATION_SCHEME} {}.{}",
        session.session_id,
        Base64UrlUnpadded::encode_string(&session.session_secret)
    )
}

async fn assert_error(
    response: axum::response::Response,
    expected_status: StatusCode,
    expected_code: &str,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(response.status(), expected_status);
    assert_catalog_headers(&response, "application/json");
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await?)?;
    assert_eq!(body["error"]["code"], expected_code);
    Ok(())
}

fn assert_catalog_headers(response: &axum::response::Response, content_type: &str) {
    assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
}

fn assert_created_and_replayed(
    first: &axum::response::Response,
    second: &axum::response::Response,
) {
    assert!(
        (first.status() == StatusCode::CREATED && second.status() == StatusCode::OK)
            || (first.status() == StatusCode::OK && second.status() == StatusCode::CREATED)
    );
}

async fn assert_redacted_status(
    response: axum::response::Response,
    expected_state: u64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    assert_catalog_headers(&response, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    let body = to_bytes(response.into_body(), 1_100_000).await?;
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(&body)? else {
        return Err("status must be a map".into());
    };
    assert_eq!(fields.len(), 6);
    assert_eq!(fields[2].1, CanonicalValue::Unsigned(expected_state));
    assert_eq!(fields[3].1, CanonicalValue::Null);
    Ok(body.to_vec())
}

async fn recovery_rows(
    harness: &support::PostgresHarness,
    identity: IdentityId,
) -> Result<(i64, i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT
            (SELECT count(*) FROM identity.recovery_scope_catalogs WHERE identity_id=$1),
            (SELECT count(*) FROM identity.recovery_scope_catalog_preparations WHERE identity_id=$1),
            (SELECT count(*) FROM identity.recovery_scope_catalog_preparations
                WHERE identity_id=$1 AND provider_response_bytes IS NOT NULL)",
    )
    .bind(identity.to_string())
    .fetch_one(harness.admin_pool())
    .await
}

fn catalog_body(
    identity: IdentityId,
    head: IdentityLogHead,
    signer: &SigningKey,
    generation: SafeUint,
    previous: Option<Sha256Digest>,
    merkle: [u8; 32],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let ciphertext = b"opaque-encrypted-catalog-v2".to_vec();
    let catalog_id = uuid::Uuid::parse_str(if generation.get() == 1 {
        "0190f2a5-7b1c-7abc-8def-0123456789b1"
    } else {
        "0190f2a5-7b1c-7abc-8def-0123456789b3"
    })?;
    let authority_device = DeviceId::from_str(AUTHORITY_DEVICE)?;
    let authority_key_id = uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b2")?;
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(catalog_id.to_string())),
        field(3, CanonicalValue::Text(identity.to_string())),
        field(4, generation.to_canonical_value()),
        field(
            5,
            previous.map_or(CanonicalValue::Null, |value| value.to_canonical_value()),
        ),
        field(6, CanonicalValue::Unsigned(1)),
        field(7, CanonicalValue::Bytes(merkle.to_vec())),
        field(
            8,
            Sha256Digest::hash_domain(CATALOG_CIPHERTEXT_HASH_DOMAIN, &ciphertext)
                .to_canonical_value(),
        ),
        field(9, head.sequence().to_canonical_value()),
        field(10, head.hash().to_canonical_value()),
        field(11, CanonicalValue::Text(authority_device.to_string())),
        field(12, CanonicalValue::Text(authority_key_id.to_string())),
        field(13, public(signer).to_canonical_value()),
        field(14, at(2_500).to_canonical_value()),
        field(15, at(250_000).to_canonical_value()),
    ]);
    let signature = domain_signature(signer, CATALOG_HEAD_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    signed_fields.push(field(16, signature.to_canonical_value()));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        field(1, CanonicalValue::Map(signed_fields)),
        field(2, CanonicalValue::Bytes(ciphertext)),
    ]))?)
}

fn preparation_body(
    request: dtx_domain::DeviceEnrollmentChallengeId,
    identity: IdentityId,
    device: DeviceId,
    signer: &SigningKey,
    recipient: [u8; 32],
    head: IdentityLogHead,
    response_capability: [u8; 32],
    catalog_id: uuid::Uuid,
    catalog_generation: SafeUint,
    catalog_head_digest: Sha256Digest,
    idempotency_key: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, CanonicalValue::Text(identity.to_string())),
        field(4, CanonicalValue::Text(catalog_id.to_string())),
        field(5, catalog_generation.to_canonical_value()),
        field(6, catalog_head_digest.to_canonical_value()),
        field(7, CanonicalValue::Text(device.to_string())),
        field(8, public(signer).to_canonical_value()),
        field(9, CanonicalValue::Bytes(recipient.to_vec())),
        field(10, head.sequence().to_canonical_value()),
        field(11, head.hash().to_canonical_value()),
        field(12, CanonicalValue::Bytes(vec![60; 32])),
        field(
            13,
            Sha256Digest::hash_domain(RESPONSE_CAPABILITY_HASH_DOMAIN, &response_capability)
                .to_canonical_value(),
        ),
        field(
            14,
            Sha256Digest::hash_domain(
                b"dirextalk.recovery-scope-catalog-handoff-preparation-idempotency.v2\0",
                idempotency_key.as_bytes(),
            )
            .to_canonical_value(),
        ),
        field(15, at(4_500).to_canonical_value()),
        field(16, at(200_000).to_canonical_value()),
    ]);
    let signature = domain_signature(signer, PREPARATION_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    signed_fields.push(field(17, signature.to_canonical_value()));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(
        signed_fields,
    ))?)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the fixture names every signed V2 response coordinate explicitly"
)]
fn provider_body(
    request: dtx_domain::DeviceEnrollmentChallengeId,
    identity: IdentityId,
    catalog_id: uuid::Uuid,
    catalog_generation: SafeUint,
    catalog_head_digest: Sha256Digest,
    preparation: &[u8],
    signed_head: &[u8],
    observed_head: IdentityLogHead,
    successor_head: IdentityLogHead,
    candidate_device: DeviceId,
    candidate_recipient: [u8; 32],
    device_add: &[u8],
    provider_device: DeviceId,
    provider_signer: &SigningKey,
    authority_device: DeviceId,
    authority_signer: &SigningKey,
    response_idempotency_key: &str,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let preparation_digest = Sha256Digest::hash_domain(PREPARATION_DIGEST_DOMAIN, preparation);
    let recipient_key_digest =
        Sha256Digest::hash_domain(RECIPIENT_KEY_HASH_DOMAIN, &candidate_recipient);
    let device_add_digest =
        Sha256Digest::hash_domain(b"dirextalk.identity-device-add.v1\0", device_add);
    let provider_descriptor = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(provider_device.to_string())),
        field(3, public(provider_signer).to_canonical_value()),
    ]);
    let authority_descriptor = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(authority_device.to_string())),
        field(3, public(authority_signer).to_canonical_value()),
    ]);
    let package = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, preparation_digest.to_canonical_value()),
        field(4, CanonicalValue::Bytes(signed_head.to_vec())),
        // The identity service remains blind to this candidate-decrypted
        // package; a canonical opaque placeholder keeps the helper bounded.
        field(5, CanonicalValue::Bytes(vec![0xa1, 0x01, 0x02])),
        field(6, CanonicalValue::Text(identity.to_string())),
        field(7, CanonicalValue::Text(catalog_id.to_string())),
        field(8, catalog_generation.to_canonical_value()),
        field(9, CanonicalValue::Text(candidate_device.to_string())),
        field(10, CanonicalValue::Bytes(candidate_recipient.to_vec())),
        field(11, observed_head.sequence().to_canonical_value()),
        field(12, observed_head.hash().to_canonical_value()),
        field(13, successor_head.sequence().to_canonical_value()),
        field(14, successor_head.hash().to_canonical_value()),
        field(15, device_add_digest.to_canonical_value()),
        field(16, issued_at.to_canonical_value()),
        field(17, expires_at.to_canonical_value()),
    ]);
    let package_bytes = encode_deterministic_cbor(&package)?;
    let package_digest = Sha256Digest::hash_domain(PROVIDER_PACKAGE_DIGEST_DOMAIN, &package_bytes);

    let response_idempotency_digest = Sha256Digest::hash_domain(
        b"dirextalk.recovery-scope-catalog-handoff-response-idempotency.v2\0",
        response_idempotency_key.as_bytes(),
    );
    let aad = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, preparation_digest.to_canonical_value()),
        field(4, CanonicalValue::Text(identity.to_string())),
        field(5, CanonicalValue::Text(catalog_id.to_string())),
        field(6, catalog_generation.to_canonical_value()),
        field(7, catalog_head_digest.to_canonical_value()),
        field(8, CanonicalValue::Text(candidate_device.to_string())),
        field(9, recipient_key_digest.to_canonical_value()),
        field(10, observed_head.sequence().to_canonical_value()),
        field(11, observed_head.hash().to_canonical_value()),
        field(12, successor_head.sequence().to_canonical_value()),
        field(13, successor_head.hash().to_canonical_value()),
        field(14, device_add_digest.to_canonical_value()),
        field(15, provider_descriptor.clone()),
        field(16, authority_descriptor.clone()),
        field(17, package_digest.to_canonical_value()),
        field(18, response_idempotency_digest.to_canonical_value()),
        field(19, issued_at.to_canonical_value()),
        field(20, expires_at.to_canonical_value()),
    ]);
    let aad_bytes = encode_deterministic_cbor(&aad)?;
    let aad_digest = Sha256Digest::hash_domain(PROVIDER_AAD_DIGEST_DOMAIN, &aad_bytes);

    // Structural RFC 9180 base-mode envelope: a fresh non-low-order X25519
    // encapsulation and ciphertext including the required ChaCha20-Poly1305
    // authentication tag. The identity service intentionally does not decrypt.
    let envelope = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Bytes(vec![7; 32])),
        field(3, CanonicalValue::Bytes(vec![8; 17])),
    ]);
    let envelope_bytes = encode_deterministic_cbor(&envelope)?;
    let envelope_digest =
        Sha256Digest::hash_domain(PROVIDER_CIPHERTEXT_HASH_DOMAIN, &envelope_bytes);

    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, preparation_digest.to_canonical_value()),
        field(4, CanonicalValue::Text(identity.to_string())),
        field(5, CanonicalValue::Text(catalog_id.to_string())),
        field(6, catalog_generation.to_canonical_value()),
        field(7, catalog_head_digest.to_canonical_value()),
        field(8, CanonicalValue::Text(candidate_device.to_string())),
        field(9, recipient_key_digest.to_canonical_value()),
        field(10, observed_head.sequence().to_canonical_value()),
        field(11, observed_head.hash().to_canonical_value()),
        field(12, successor_head.sequence().to_canonical_value()),
        field(13, successor_head.hash().to_canonical_value()),
        field(14, device_add_digest.to_canonical_value()),
        field(15, provider_descriptor),
        field(16, authority_descriptor),
        field(17, package_digest.to_canonical_value()),
        field(18, aad_digest.to_canonical_value()),
        field(19, envelope_digest.to_canonical_value()),
        field(20, response_idempotency_digest.to_canonical_value()),
        field(21, issued_at.to_canonical_value()),
        field(22, expires_at.to_canonical_value()),
    ]);
    let provider_signature = domain_signature(
        provider_signer,
        PROVIDER_RESPONSE_SIGNATURE_DOMAIN,
        &unsigned,
    )?;
    let authority_signature = domain_signature(
        authority_signer,
        PROVIDER_AUTHORITY_SIGNATURE_DOMAIN,
        &unsigned,
    )?;
    let CanonicalValue::Map(mut fields) = unsigned else {
        unreachable!()
    };
    fields.push(field(23, provider_signature.to_canonical_value()));
    fields.push(field(24, authority_signature.to_canonical_value()));
    fields.push(field(25, CanonicalValue::Bytes(device_add.to_vec())));
    fields.push(field(26, envelope));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(fields))?)
}

fn genesis(root: &SigningKey, recovery: &SigningKey) -> IdentityLogEventV1 {
    let root_key = public(root);
    let recovery_key = public(recovery);
    let identity = IdentityId::derive(root_key.as_domain_key());
    signed_event(
        root,
        identity,
        1,
        None,
        1_000,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature: signature(
                recovery,
                &genesis_recovery_acceptance_input(identity, root_key, recovery_key).unwrap(),
            ),
        },
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "test fixture names every signed device-add binding explicitly"
)]
fn device_add(
    root: &SigningKey,
    identity: IdentityId,
    device: DeviceId,
    key: &SigningKey,
    encryption: u8,
    sequence: u64,
    previous: Sha256Digest,
    time: i64,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity,
        device,
        public(key),
        DeviceEncryptionPublicKey::try_from([encryption; 32]).unwrap(),
        public(root),
        at(time),
    )
    .unwrap();
    let certificate = DeviceCertificateV1::signed(
        unsigned.clone(),
        signature(
            root,
            &device_certificate_signature_input(unsigned.signing_digest().unwrap()),
        ),
    )
    .unwrap();
    signed_event(
        root,
        identity,
        sequence,
        Some(previous),
        time,
        IdentityLogEventPayloadV1::DeviceAdd { certificate },
    )
}

fn signed_event(
    signer: &SigningKey,
    identity: IdentityId,
    sequence: u64,
    previous: Option<Sha256Digest>,
    time: i64,
    payload: IdentityLogEventPayloadV1,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity,
        safe(sequence),
        previous,
        at(time),
        payload,
        public(signer),
    )
    .unwrap();
    IdentityLogEventV1::signed(
        unsigned.clone(),
        signature(
            signer,
            &identity_log_signature_input(unsigned.signing_digest().unwrap()),
        ),
    )
    .unwrap()
}

fn append_command(
    seed: u8,
    expected: Option<IdentityLogHead>,
    event: &IdentityLogEventV1,
) -> Result<IdentityAppendCommand, Box<dyn Error>> {
    Ok(IdentityAppendCommand::new(
        Sha256Digest::from_bytes([seed; 32]),
        expected,
        event.to_deterministic_cbor()?,
    )?)
}

fn committed(outcome: IdentityAppendOutcome) -> Result<IdentityLogHead, Box<dyn Error>> {
    match outcome {
        IdentityAppendOutcome::Committed(receipt) => Ok(receipt.head()),
        other => Err(format!("expected committed identity head: {other:?}").into()),
    }
}

fn domain_signature(
    key: &SigningKey,
    domain: &[u8],
    value: &CanonicalValue,
) -> Result<Ed25519Signature, Box<dyn Error>> {
    let mut input = domain.to_vec();
    input.extend_from_slice(&encode_deterministic_cbor(value)?);
    Ok(signature(key, &input))
}

fn field(key: u64, value: CanonicalValue) -> (CanonicalValue, CanonicalValue) {
    (CanonicalValue::Unsigned(key), value)
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).unwrap()
}

fn signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}

fn safe(value: u64) -> SafeUint {
    SafeUint::new(value).unwrap()
}

fn at(value: i64) -> UtcMillis {
    UtcMillis::new(value).unwrap()
}

async fn wait_for_exact_advisory_waiters(
    pool: &sqlx::PgPool,
    lock_key: i64,
    applications: &[&str],
) -> Result<(), Box<dyn Error>> {
    let class_id = i64::from((lock_key as u64 >> 32) as u32);
    let object_id = i64::from(lock_key as u32);
    let applications: Vec<String> = applications.iter().map(ToString::to_string).collect();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let backends: Vec<(String, i32)> = sqlx::query_as(
                "SELECT application_name,pid FROM pg_stat_activity WHERE datid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND application_name=ANY($1) ORDER BY application_name",
            )
            .bind(&applications)
            .fetch_all(pool)
            .await?;
            let pids: Vec<i32> = backends.iter().map(|(_, pid)| *pid).collect();
            let waiting: Vec<i32> = if pids.len() == applications.len()
                && pids.iter().copied().collect::<std::collections::BTreeSet<_>>().len()
                    == pids.len()
            {
                sqlx::query_scalar(
                    "SELECT pid FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND locktype='advisory' AND classid=$1 AND objid=$2 AND objsubid=1 AND granted=false AND pid=ANY($3) ORDER BY pid",
                )
                .bind(class_id)
                .bind(object_id)
                .bind(&pids)
                .fetch_all(pool)
                .await?
            } else {
                Vec::new()
            };
            if pids.len() == applications.len()
                && waiting.len() == pids.len()
                && waiting.iter().copied().collect::<std::collections::BTreeSet<_>>()
                    == pids.iter().copied().collect()
            {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "advisory lock waiters did not reach the deterministic gate")??;
    Ok(())
}

struct TestClock(AtomicI64);

impl TestClock {
    const fn new(value: i64) -> Self {
        Self(AtomicI64::new(value))
    }

    fn set(&self, value: i64) {
        self.0.store(value, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_utc_millis(&self) -> Result<i64, ClockError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    include!("fixtures/recovery_catalog_workflow.inc.rs");
}
