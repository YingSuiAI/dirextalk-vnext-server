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
    DEVICE_SESSION_RECEIPT_CONTENT_TYPE, IDENTITY_APPEND_RECEIPT_CONTENT_TYPE,
    IDENTITY_BOOTSTRAP_PATH, IDENTITY_LOG_EVENT_CONTENT_TYPE, INITIAL_DEVICE_ENROLL_PATH,
    IdentityBootstrapState, identity_bootstrap_router_with_state,
    parse_device_session_authorization,
};
use dtx_identity_persistence::{
    DEVICE_SESSION_SECRET_HASH_DOMAIN, DeviceSessionCompletionCommand, DeviceSessionCredential,
    DeviceSessionRepository, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogRepository,
    IdentityPgStore, device_session_proof_input,
};
use dtx_wire::{
    CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey, UtcMillis,
    decode_deterministic_cbor, encode_deterministic_cbor,
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

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one security-boundary test keeps bootstrap, first-device, session replay, consumption, and revoke assertions coherent"
)]
async fn initial_device_and_short_session_are_self_authenticated_replayable_and_revocable()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            store.clone(),
            Arc::new(FixedClock(2_000)),
            AUDIENCE,
        ),
    );

    let root = signing_key(1);
    let recovery = signing_key(2);
    let genesis = genesis(&root, &recovery, 1_000)?;
    let identity_id = genesis.identity_id();
    let genesis_bytes = genesis.to_deterministic_cbor()?;
    let bootstrap = send_event(
        app.clone(),
        IDENTITY_BOOTSTRAP_PATH,
        BOOTSTRAP_KEY,
        None,
        genesis_bytes,
    )
    .await?;
    assert_eq!(bootstrap.status(), StatusCode::CREATED);
    assert_eq!(
        bootstrap
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(IDENTITY_APPEND_RECEIPT_CONTENT_TYPE)
    );

    let device = signing_key(3);
    let device_id = DeviceId::new();
    let initial = device_add(
        &root,
        &device,
        identity_id,
        device_id,
        genesis.entry_hash()?,
        2,
        1_100,
    )?;
    let initial_bytes = initial.to_deterministic_cbor()?;
    let initial_response = send_event(
        app.clone(),
        INITIAL_DEVICE_ENROLL_PATH,
        INITIAL_DEVICE_KEY,
        Some(genesis.entry_hash()?),
        initial_bytes.clone(),
    )
    .await?;
    assert_eq!(initial_response.status(), StatusCode::CREATED);
    let initial_receipt = to_bytes(initial_response.into_body(), 16_384)
        .await?
        .to_vec();
    let initial_replay = send_event(
        app.clone(),
        INITIAL_DEVICE_ENROLL_PATH,
        INITIAL_DEVICE_KEY,
        Some(genesis.entry_hash()?),
        initial_bytes,
    )
    .await?;
    assert_eq!(initial_replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(initial_replay.into_body(), 16_384).await?.to_vec(),
        initial_receipt
    );
    assert_identity_entry_count(harness.identity_runtime_pool(), identity_id, 2).await?;

    let challenge_request = Request::builder()
        .method("POST")
        .uri(DEVICE_SESSION_CHALLENGE_PATH)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({
            "identity_id": identity_id,
            "device_id": device_id,
        }))?))?;
    let challenge_response = app.clone().oneshot(challenge_request).await?;
    assert_eq!(challenge_response.status(), StatusCode::CREATED);
    let challenge: serde_json::Value =
        serde_json::from_slice(&to_bytes(challenge_response.into_body(), 16_384).await?)?;
    let challenge_id: DeviceSessionChallengeId = challenge
        .pointer("/challenge_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("challenge ID missing")?
        .parse()?;
    let challenge_nonce = decode_32(
        challenge
            .pointer("/challenge_nonce")
            .and_then(serde_json::Value::as_str)
            .ok_or("challenge nonce missing")?,
    )?;
    assert_eq!(
        challenge
            .pointer("/audience")
            .and_then(serde_json::Value::as_str),
        Some(AUDIENCE)
    );
    let session_expires_at = UtcMillis::new(
        challenge
            .pointer("/session_expires_at_ms")
            .and_then(serde_json::Value::as_i64)
            .ok_or("session expiry missing")?,
    )?;
    assert_challenge_stores_only_hash(
        harness.identity_runtime_pool(),
        challenge_id,
        challenge_nonce,
    )
    .await?;
    let rate_limited = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(DEVICE_SESSION_CHALLENGE_PATH)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "identity_id": identity_id,
                    "device_id": device_id,
                }))?))?,
        )
        .await?;
    assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_safe_error(rate_limited, "DEVICE_SESSION_CHALLENGE_RATE_LIMITED").await?;

    let session_id = DeviceSessionId::new();
    let session_secret = [9_u8; 32];
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let proof = signature(
        &device,
        &device_session_proof_input(
            identity_id,
            device_id,
            challenge_id,
            &challenge_nonce,
            AUDIENCE,
            session_id,
            session_secret_hash,
            session_expires_at,
        )?,
    );
    let completion_body = json!({
        "identity_id": identity_id,
        "device_id": device_id,
        "challenge_id": challenge_id,
        "session_id": session_id,
        "challenge_nonce": Base64UrlUnpadded::encode_string(&challenge_nonce),
        "session_secret": Base64UrlUnpadded::encode_string(&session_secret),
        "proof": proof,
    });
    let completion = send_session(app.clone(), SESSION_KEY, completion_body.clone()).await?;
    assert_eq!(completion.status(), StatusCode::CREATED);
    assert_eq!(
        completion
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(DEVICE_SESSION_RECEIPT_CONTENT_TYPE)
    );
    let receipt = to_bytes(completion.into_body(), 16_384).await?.to_vec();
    let replay = send_session(app.clone(), SESSION_KEY, completion_body.clone()).await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(replay.into_body(), 16_384).await?.to_vec(),
        receipt
    );
    assert_session_count(harness.identity_runtime_pool(), 1).await?;

    let mut altered = completion_body.clone();
    altered["session_secret"] =
        serde_json::Value::String(Base64UrlUnpadded::encode_string(&[8_u8; 32]));
    let idempotency_conflict = send_session(app.clone(), SESSION_KEY, altered).await?;
    assert_eq!(idempotency_conflict.status(), StatusCode::CONFLICT);
    assert_safe_error(idempotency_conflict, "IDEMPOTENCY_CONFLICT").await?;

    let consumed = send_session(app.clone(), SESSION_RETRY_KEY, completion_body).await?;
    assert_eq!(consumed.status(), StatusCode::CONFLICT);
    assert_safe_error(consumed, "DEVICE_SESSION_CHALLENGE_CONSUMED").await?;
    assert_session_count(harness.identity_runtime_pool(), 1).await?;

    let credential = DeviceSessionCredential::new(session_id, session_secret)?;
    let authenticated = DeviceSessionRepository
        .authenticate(&store, &credential, UtcMillis::new(2_001)?)
        .await?;
    assert_eq!(authenticated.identity_id(), identity_id);
    assert_eq!(authenticated.device_id(), device_id);

    let mut authorization = HeaderMap::new();
    authorization.insert(
        header::AUTHORIZATION,
        format!(
            "{DEVICE_SESSION_AUTHORIZATION_SCHEME} {session_id}.{}",
            Base64UrlUnpadded::encode_string(&session_secret)
        )
        .parse()?,
    );
    let parsed_credential = parse_device_session_authorization(&authorization)?;
    assert_eq!(parsed_credential.session_id(), session_id);
    let parsed_authenticated = DeviceSessionRepository
        .authenticate(&store, &parsed_credential, UtcMillis::new(2_001)?)
        .await?;
    assert_eq!(parsed_authenticated.device_id(), device_id);
    authorization.append(header::AUTHORIZATION, "Bearer ignored".parse()?);
    assert!(parse_device_session_authorization(&authorization).is_err());

    let expired = DeviceSessionRepository
        .authenticate(&store, &credential, session_expires_at)
        .await;
    assert!(matches!(
        expired,
        Err(dtx_identity_persistence::IdentityPersistenceError::DeviceAuthenticationRejected)
    ));

    let expired_challenge = DeviceSessionRepository
        .issue_challenge(
            &store,
            identity_id,
            device_id,
            [7_u8; 32],
            AUDIENCE,
            UtcMillis::new(20_000)?,
        )
        .await?;
    let expired_session_id = DeviceSessionId::new();
    let expired_session_secret = [6_u8; 32];
    let expired_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &expired_session_secret);
    let expired_proof = signature(
        &device,
        &device_session_proof_input(
            identity_id,
            device_id,
            expired_challenge.challenge_id(),
            expired_challenge.nonce(),
            AUDIENCE,
            expired_session_id,
            expired_secret_hash,
            expired_challenge.session_expires_at(),
        )?,
    );
    let expired_app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            store.clone(),
            Arc::new(FixedClock(expired_challenge.expires_at().get())),
            AUDIENCE,
        ),
    );
    let expired_completion = send_session(
        expired_app,
        EXPIRED_SESSION_KEY,
        json!({
            "identity_id": identity_id,
            "device_id": device_id,
            "challenge_id": expired_challenge.challenge_id(),
            "session_id": expired_session_id,
            "challenge_nonce": Base64UrlUnpadded::encode_string(expired_challenge.nonce()),
            "session_secret": Base64UrlUnpadded::encode_string(&expired_session_secret),
            "proof": expired_proof,
        }),
    )
    .await?;
    assert_eq!(expired_completion.status(), StatusCode::CONFLICT);
    assert_safe_error(expired_completion, "DEVICE_SESSION_CHALLENGE_EXPIRED").await?;

    let repository = IdentityLogRepository::new();
    let head = repository
        .load(&store, identity_id)
        .await?
        .ok_or("identity log missing before revoke")?
        .head();
    let revoke = signed_event(
        &root,
        identity_id,
        3,
        Some(head.hash()),
        30_000,
        IdentityLogEventPayloadV1::DeviceRevoke { device_id },
    )?;
    let revoke_command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-device-session-revoke\0", b"1"),
        Some(head),
        revoke.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append(&store, &revoke_command, UtcMillis::new(30_000)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let revoked = DeviceSessionRepository
        .authenticate(&store, &credential, UtcMillis::new(2_101)?)
        .await;
    assert!(matches!(
        revoked,
        Err(dtx_identity_persistence::IdentityPersistenceError::DeviceAuthenticationRejected)
    ));
    let removed = DeviceSessionRepository
        .prune_expired(&store, expired_challenge.session_expires_at())
        .await?;
    assert_eq!(removed, 5);
    assert_device_session_state_counts(harness.identity_runtime_pool(), (0, 0, 0, 0)).await?;
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one HTTP/SQL regression protects an approved QR enrollment when its first success response is lost"
)]
async fn approved_device_enrollment_replays_after_approving_session_is_revoked()
-> Result<(), Box<dyn Error>> {
    const ENROLLMENT_CHALLENGE_KEY: &str = "device-enrollment-challenge-0001";
    const ENROLLMENT_APPROVAL_KEY: &str = "device-enrollment-approval-0001";
    const DIFFERENT_ENROLLMENT_APPROVAL_KEY: &str = "device-enrollment-approval-0002";

    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            store.clone(),
            Arc::new(FixedClock(2_000)),
            AUDIENCE,
        ),
    );

    let root = signing_key(41);
    let recovery = signing_key(42);
    let genesis = genesis(&root, &recovery, 1_000)?;
    let identity_id = genesis.identity_id();
    let bootstrap = send_event(
        app.clone(),
        IDENTITY_BOOTSTRAP_PATH,
        "device-enrollment-bootstrap-0001",
        None,
        genesis.to_deterministic_cbor()?,
    )
    .await?;
    assert_eq!(bootstrap.status(), StatusCode::CREATED);

    let approving_device = signing_key(43);
    let approving_device_id = DeviceId::new();
    let initial_device = device_add(
        &root,
        &approving_device,
        identity_id,
        approving_device_id,
        genesis.entry_hash()?,
        2,
        1_100,
    )?;
    let initial_head_hash = initial_device.entry_hash()?;
    let initial = send_event(
        app.clone(),
        INITIAL_DEVICE_ENROLL_PATH,
        "device-enrollment-initial-0001",
        Some(genesis.entry_hash()?),
        initial_device.to_deterministic_cbor()?,
    )
    .await?;
    assert_eq!(initial.status(), StatusCode::CREATED);

    let session_challenge = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(DEVICE_SESSION_CHALLENGE_PATH)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "identity_id": identity_id,
                    "device_id": approving_device_id,
                }))?))?,
        )
        .await?;
    assert_eq!(session_challenge.status(), StatusCode::CREATED);
    let session_challenge: serde_json::Value =
        serde_json::from_slice(&to_bytes(session_challenge.into_body(), 16_384).await?)?;
    let session_challenge_id: DeviceSessionChallengeId = session_challenge
        .pointer("/challenge_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("device session challenge ID missing")?
        .parse()?;
    let session_challenge_nonce = decode_32(
        session_challenge
            .pointer("/challenge_nonce")
            .and_then(serde_json::Value::as_str)
            .ok_or("device session challenge nonce missing")?,
    )?;
    let session_expires_at = UtcMillis::new(
        session_challenge
            .pointer("/session_expires_at_ms")
            .and_then(serde_json::Value::as_i64)
            .ok_or("device session expiry missing")?,
    )?;
    let approving_session_id = DeviceSessionId::new();
    let approving_session_secret = [44_u8; 32];
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &approving_session_secret);
    let session_completion = send_session(
        app.clone(),
        "device-enrollment-session-0001",
        json!({
            "identity_id": identity_id,
            "device_id": approving_device_id,
            "challenge_id": session_challenge_id,
            "session_id": approving_session_id,
            "challenge_nonce": Base64UrlUnpadded::encode_string(&session_challenge_nonce),
            "session_secret": Base64UrlUnpadded::encode_string(&approving_session_secret),
            "proof": signature(
                &approving_device,
                &device_session_proof_input(
                    identity_id,
                    approving_device_id,
                    session_challenge_id,
                    &session_challenge_nonce,
                    AUDIENCE,
                    approving_session_id,
                    session_secret_hash,
                    session_expires_at,
                )?,
            ),
        }),
    )
    .await?;
    assert_eq!(session_completion.status(), StatusCode::CREATED);

    let candidate_device = signing_key(45);
    let candidate_device_id = DeviceId::new();
    let enrollment_capability = [46_u8; 32];
    let candidate_request = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(candidate_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Bytes(public_key(&candidate_device)?.as_bytes().to_vec()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Bytes(vec![8; 32]),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Bytes(enrollment_capability.to_vec()),
        ),
    ]))?;
    let candidate_response =
        send_device_enrollment_challenge(app.clone(), ENROLLMENT_CHALLENGE_KEY, candidate_request)
            .await?;
    assert_eq!(candidate_response.status(), StatusCode::CREATED);
    let candidate_response = to_bytes(candidate_response.into_body(), 16_384).await?;
    let enrollment_challenge_id = enrollment_challenge_id(&candidate_response)?;

    let enrollment_event = device_add_with_encryption(
        &root,
        &candidate_device,
        &DeviceAddInput {
            identity_id,
            device_id: candidate_device_id,
            previous_hash: initial_head_hash,
            sequence: 3,
            occurred_at: 1_200,
            encryption_key: [8_u8; 32],
        },
    )?;
    let enrollment_body = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(enrollment_challenge_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Bytes(enrollment_capability.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Bytes(enrollment_event.to_deterministic_cbor()?),
        ),
    ]))?;
    let approved = send_device_enrollment_approval(
        app.clone(),
        ENROLLMENT_APPROVAL_KEY,
        approving_session_id,
        approving_session_secret,
        initial_head_hash,
        enrollment_body.clone(),
    )
    .await?;
    assert_eq!(approved.status(), StatusCode::CREATED);
    let approved_receipt = to_bytes(approved.into_body(), 16_384).await?.to_vec();
    assert!(!approved_receipt.is_empty());
    assert_identity_entry_count(harness.identity_runtime_pool(), identity_id, 3).await?;

    // Simulate a later revoke after the approval committed but before a caller
    // can retry the response-lost approval request. The direct append is only
    // the test setup for server-side state; both approval attempts above/below
    // traverse the public HTTP boundary.
    let repository = IdentityLogRepository::new();
    let enrollment_head = repository
        .load(&store, identity_id)
        .await?
        .ok_or("identity log missing before device session revoke")?
        .head();
    let revoke = signed_event(
        &root,
        identity_id,
        4,
        Some(enrollment_head.hash()),
        3_000,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: approving_device_id,
        },
    )?;
    let revoke_command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-device-enrollment-revoke\0", b"1"),
        Some(enrollment_head),
        revoke.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append(&store, &revoke_command, UtcMillis::new(3_000)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let credential = DeviceSessionCredential::new(approving_session_id, approving_session_secret)?;
    assert!(matches!(
        DeviceSessionRepository
            .authenticate(&store, &credential, UtcMillis::new(3_001)?)
            .await,
        Err(dtx_identity_persistence::IdentityPersistenceError::DeviceAuthenticationRejected)
    ));

    let replay = send_device_enrollment_approval(
        app.clone(),
        ENROLLMENT_APPROVAL_KEY,
        approving_session_id,
        approving_session_secret,
        initial_head_hash,
        enrollment_body.clone(),
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(replay.into_body(), 16_384).await?.to_vec(),
        approved_receipt
    );

    let different_idempotency_key = send_device_enrollment_approval(
        app,
        DIFFERENT_ENROLLMENT_APPROVAL_KEY,
        approving_session_id,
        approving_session_secret,
        initial_head_hash,
        enrollment_body,
    )
    .await?;
    assert_eq!(different_idempotency_key.status(), StatusCode::CONFLICT);
    assert_safe_error(different_idempotency_key, "IDEMPOTENCY_CONFLICT").await?;
    assert_identity_entry_count(harness.identity_runtime_pool(), identity_id, 4).await?;
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL HTTP boundary test protects revoke authorization, exact replay, and target binding"
)]
async fn another_device_revoke_is_root_signed_session_gated_and_exactly_replayable()
-> Result<(), Box<dyn Error>> {
    const REVOKE_KEY: &str = "device-revoke-command-0001";
    const REVOKE_SELF_KEY: &str = "device-revoke-command-0002";
    const REVOKE_AFTER_SESSION_KEY: &str = "device-revoke-command-0003";

    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let repository = IdentityLogRepository::new();
    let root = signing_key(61);
    let recovery = signing_key(62);
    let genesis = genesis(&root, &recovery, 1_000)?;
    let identity_id = genesis.identity_id();
    let genesis_command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-device-revoke-bootstrap\0", b"1"),
        None,
        genesis.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append(&store, &genesis_command, UtcMillis::new(1_000)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));

    let initiator = signing_key(63);
    let initiator_device_id = DeviceId::new();
    let initiator_add = device_add(
        &root,
        &initiator,
        identity_id,
        initiator_device_id,
        genesis.entry_hash()?,
        2,
        1_100,
    )?;
    let genesis_head = repository
        .load(&store, identity_id)
        .await?
        .ok_or("identity missing after bootstrap")?
        .head();
    let initiator_add_command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-device-revoke-add\0", b"1"),
        Some(genesis_head),
        initiator_add.to_deterministic_cbor()?,
    )?;
    repository
        .append(&store, &initiator_add_command, UtcMillis::new(1_100)?)
        .await?;

    let target = signing_key(64);
    let target_device_id = DeviceId::new();
    let target_add = device_add_with_encryption(
        &root,
        &target,
        &DeviceAddInput {
            identity_id,
            device_id: target_device_id,
            previous_hash: initiator_add.entry_hash()?,
            sequence: 3,
            occurred_at: 1_200,
            encryption_key: [8_u8; 32],
        },
    )?;
    let initiator_head = repository
        .load(&store, identity_id)
        .await?
        .ok_or("identity missing after initiator enrollment")?
        .head();
    let target_add_command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-device-revoke-add\0", b"2"),
        Some(initiator_head),
        target_add.to_deterministic_cbor()?,
    )?;
    repository
        .append(&store, &target_add_command, UtcMillis::new(1_200)?)
        .await?;

    let session_nonce = [65_u8; 32];
    let challenge = DeviceSessionRepository
        .issue_challenge(
            &store,
            identity_id,
            initiator_device_id,
            session_nonce,
            AUDIENCE,
            UtcMillis::new(1_300)?,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let session_secret = [66_u8; 32];
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let session_proof = signature(
        &initiator,
        &device_session_proof_input(
            identity_id,
            initiator_device_id,
            challenge.challenge_id(),
            challenge.nonce(),
            AUDIENCE,
            session_id,
            session_secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    let session_completion = DeviceSessionCompletionCommand::new(
        Sha256Digest::hash_domain(b"test-device-revoke-session\0", b"1"),
        identity_id,
        initiator_device_id,
        challenge.challenge_id(),
        session_id,
        session_nonce,
        session_secret,
        session_proof,
    )?;
    DeviceSessionRepository
        .complete(&store, &session_completion, UtcMillis::new(1_301)?)
        .await?;

    let app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            store.clone(),
            Arc::new(FixedClock(1_400)),
            AUDIENCE,
        ),
    );
    let target_head = repository
        .load(&store, identity_id)
        .await?
        .ok_or("identity missing after target enrollment")?
        .head();
    let revoke_target = signed_event(
        &root,
        identity_id,
        4,
        Some(target_head.hash()),
        1_400,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: target_device_id,
        },
    )?;
    let revoke_target_bytes = revoke_target.to_deterministic_cbor()?;

    let invalid_session = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        [99_u8; 32],
        identity_id,
        target_device_id,
        target_head.hash(),
        revoke_target_bytes.clone(),
    )
    .await?;
    assert_eq!(invalid_session.status(), StatusCode::UNAUTHORIZED);
    assert_safe_error(invalid_session, "DEVICE_AUTHENTICATION_FAILED").await?;

    let route_target_mismatch = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        session_secret,
        identity_id,
        DeviceId::new(),
        target_head.hash(),
        revoke_target_bytes.clone(),
    )
    .await?;
    assert_eq!(
        route_target_mismatch.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_safe_error(route_target_mismatch, "DEVICE_REVOKE_INVALID").await?;

    let revoke_current_session = signed_event(
        &root,
        identity_id,
        4,
        Some(target_head.hash()),
        1_400,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: initiator_device_id,
        },
    )?;
    let current_session_rejected = send_device_revoke(
        app.clone(),
        REVOKE_SELF_KEY,
        session_id,
        session_secret,
        identity_id,
        initiator_device_id,
        target_head.hash(),
        revoke_current_session.to_deterministic_cbor()?,
    )
    .await?;
    assert_eq!(current_session_rejected.status(), StatusCode::CONFLICT);
    assert_safe_error(
        current_session_rejected,
        "DEVICE_REVOKE_CURRENT_SESSION_FORBIDDEN",
    )
    .await?;

    let committed = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        session_secret,
        identity_id,
        target_device_id,
        target_head.hash(),
        revoke_target_bytes.clone(),
    )
    .await?;
    assert_eq!(committed.status(), StatusCode::CREATED);
    assert_eq!(
        committed
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(IDENTITY_APPEND_RECEIPT_CONTENT_TYPE)
    );
    let exact_receipt = to_bytes(committed.into_body(), 16_384).await?.to_vec();

    let response_loss_replay = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        session_secret,
        identity_id,
        target_device_id,
        target_head.hash(),
        revoke_target_bytes.clone(),
    )
    .await?;
    assert_eq!(response_loss_replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response_loss_replay.into_body(), 16_384)
            .await?
            .to_vec(),
        exact_receipt
    );

    let altered_revoke = signed_event(
        &root,
        identity_id,
        4,
        Some(target_head.hash()),
        1_401,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: target_device_id,
        },
    )?;
    let key_body_conflict = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        session_secret,
        identity_id,
        target_device_id,
        target_head.hash(),
        altered_revoke.to_deterministic_cbor()?,
    )
    .await?;
    assert_eq!(key_body_conflict.status(), StatusCode::CONFLICT);
    assert_safe_error(key_body_conflict, "IDEMPOTENCY_CONFLICT").await?;

    let post_target_revoke_replay = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        session_secret,
        identity_id,
        target_device_id,
        target_head.hash(),
        revoke_target_bytes.clone(),
    )
    .await?;
    assert_eq!(post_target_revoke_replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(post_target_revoke_replay.into_body(), 16_384)
            .await?
            .to_vec(),
        exact_receipt
    );

    let head_after_target_revoke = repository
        .load(&store, identity_id)
        .await?
        .ok_or("identity missing after target revoke")?
        .head();
    let revoke_initiator = signed_event(
        &root,
        identity_id,
        5,
        Some(head_after_target_revoke.hash()),
        1_500,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: initiator_device_id,
        },
    )?;
    let revoke_initiator_command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-device-revoke-initiator\0", b"1"),
        Some(head_after_target_revoke),
        revoke_initiator.to_deterministic_cbor()?,
    )?;
    repository
        .append(&store, &revoke_initiator_command, UtcMillis::new(1_500)?)
        .await?;

    let revoked_initiator_exact_replay = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        session_secret,
        identity_id,
        target_device_id,
        target_head.hash(),
        revoke_target_bytes.clone(),
    )
    .await?;
    assert_eq!(revoked_initiator_exact_replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(revoked_initiator_exact_replay.into_body(), 16_384)
            .await?
            .to_vec(),
        exact_receipt
    );

    let revoked_initiator_new_command = send_device_revoke(
        app,
        REVOKE_AFTER_SESSION_KEY,
        session_id,
        session_secret,
        identity_id,
        target_device_id,
        target_head.hash(),
        revoke_target_bytes,
    )
    .await?;
    assert_eq!(
        revoked_initiator_new_command.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_safe_error(
        revoked_initiator_new_command,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;
    assert_identity_entry_count(harness.identity_runtime_pool(), identity_id, 5).await?;
    Ok(())
}

async fn send_device_enrollment_challenge(
    app: axum::Router,
    idempotency_key: &str,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(DEVICE_ENROLLMENT_CHALLENGE_PATH)
            .header(
                header::CONTENT_TYPE,
                DEVICE_ENROLLMENT_CANDIDATE_CONTENT_TYPE,
            )
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
