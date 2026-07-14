#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{Clock, ClockError, DeviceId, DeviceSessionId, EnvelopeId, IdentityId, MailboxId};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_persistence::{
    DEVICE_SESSION_SECRET_HASH_DOMAIN, DeviceSessionCompletionCommand, DeviceSessionOutcome,
    DeviceSessionRepository, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogRepository,
    IdentityPgStore, device_session_proof_input,
};
use dtx_mailbox::{MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN, MailboxPersistenceError, MailboxPgStore};
use dtx_mailbox_node::{
    DEVICE_SESSION_AUTHORIZATION_SCHEME, MAILBOX_ACK_CONTENT_TYPE, MAILBOX_ACK_PATH_TEMPLATE,
    MAILBOX_ACK_RECEIPT_CONTENT_TYPE, MAILBOX_CAPABILITY_AUTHORIZATION_SCHEME,
    MAILBOX_ENQUEUE_PATH_TEMPLATE, MAILBOX_ENVELOPE_CONTENT_TYPE,
    MAILBOX_ENVELOPE_RECEIPT_CONTENT_TYPE, MAILBOX_PULL_CONTENT_TYPE, MAILBOX_PULL_PATH_TEMPLATE,
    MAILBOX_PULL_RECEIPT_CONTENT_TYPE, MAILBOX_REGISTER_CONTENT_TYPE,
    MAILBOX_REGISTER_PATH_TEMPLATE, MAILBOX_REGISTER_RECEIPT_CONTENT_TYPE, MailboxNodeState,
    mailbox_router_with_state,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use tower::ServiceExt;

const AUDIENCE: &str = "https://mailbox.test";
const NOW: i64 = 2_000;
const EXPIRY: i64 = 600_000;

#[tokio::test]
async fn mailbox_store_rejects_group_scope_grant() -> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    sqlx::query("GRANT USAGE ON SCHEMA groups TO dtx_mailbox_runtime")
        .execute(harness.admin_pool())
        .await?;

    assert!(matches!(
        MailboxPgStore::connect(harness.mailbox_runtime_options(), 1).await,
        Err(MailboxPersistenceError::RuntimeRoleOverprivileged)
    ));
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one HTTP/PostgreSQL boundary test keeps mailbox replay, non-consuming pull, revocation, and quota serialization coherent"
)]
async fn opaque_mailbox_is_replay_safe_non_consuming_and_owner_revocation_safe()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(NOW)),
    ));
    let owner = enroll_active_device(&identity_store, 81, 82, 83, [84; 32]).await?;

    let mailbox_id = MailboxId::new();
    let capability = [85; 32];
    let registration_body = mailbox_registration_body(
        mailbox_id,
        owner.identity_id,
        owner.device_id,
        capability,
        UtcMillis::new(EXPIRY)?,
    )?;
    let registration = send_registration(
        app.clone(),
        "mailbox-register-0001",
        owner.session_id,
        owner.session_secret,
        mailbox_id,
        registration_body.clone(),
    )
    .await?;
    assert_eq!(registration.status(), StatusCode::CREATED);
    assert_content_type(&registration, MAILBOX_REGISTER_RECEIPT_CONTENT_TYPE);
    let registration_receipt = response_bytes(registration).await?;
    let registration_replay = send_registration(
        app.clone(),
        "mailbox-register-0001",
        owner.session_id,
        owner.session_secret,
        mailbox_id,
        registration_body.clone(),
    )
    .await?;
    assert_eq!(registration_replay.status(), StatusCode::OK);
    assert_eq!(
        response_bytes(registration_replay).await?,
        registration_receipt
    );

    let invalid_capability_envelope_id = EnvelopeId::new();
    let unavailable = send_envelope(
        app.clone(),
        "mailbox-invalid-cap-01",
        [86; 32],
        mailbox_id,
        invalid_capability_envelope_id,
        mailbox_envelope_body(
            invalid_capability_envelope_id,
            &[0x55],
            UtcMillis::new(EXPIRY)?,
        )?,
    )
    .await?;
    assert_mailbox_error(unavailable, StatusCode::NOT_FOUND, "MAILBOX_UNAVAILABLE").await?;

    let envelope_id = EnvelopeId::new();
    let envelope_body = mailbox_envelope_body(
        envelope_id,
        &[0x6d, 0x6c, 0x73, 0x2d, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72],
        UtcMillis::new(EXPIRY)?,
    )?;
    let enqueue = send_envelope(
        app.clone(),
        "mailbox-enqueue-0001",
        capability,
        mailbox_id,
        envelope_id,
        envelope_body.clone(),
    )
    .await?;
    assert_eq!(enqueue.status(), StatusCode::CREATED);
    assert_content_type(&enqueue, MAILBOX_ENVELOPE_RECEIPT_CONTENT_TYPE);
    let enqueue_receipt = response_bytes(enqueue).await?;
    let enqueue_replay = send_envelope(
        app.clone(),
        "mailbox-enqueue-0001",
        capability,
        mailbox_id,
        envelope_id,
        envelope_body,
    )
    .await?;
    assert_eq!(enqueue_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(enqueue_replay).await?, enqueue_receipt);

    let pull_body = mailbox_pull_body(SafeUint::new(0)?, 100)?;
    let first_pull = send_pull(
        app.clone(),
        owner.session_id,
        owner.session_secret,
        mailbox_id,
        pull_body.clone(),
    )
    .await?;
    assert_eq!(first_pull.status(), StatusCode::OK);
    assert_content_type(&first_pull, MAILBOX_PULL_RECEIPT_CONTENT_TYPE);
    let first_pull_receipt = response_bytes(first_pull).await?;
    assert_pull_receipt(
        &first_pull_receipt,
        mailbox_id,
        envelope_id,
        &[0x6d, 0x6c, 0x73, 0x2d, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72],
    )?;
    let repeated_pull = send_pull(
        app.clone(),
        owner.session_id,
        owner.session_secret,
        mailbox_id,
        pull_body,
    )
    .await?;
    assert_eq!(repeated_pull.status(), StatusCode::OK);
    assert_eq!(response_bytes(repeated_pull).await?, first_pull_receipt);

    let acknowledgement_body = mailbox_ack_body(&[envelope_id])?;
    let acknowledgement = send_acknowledgement(
        app.clone(),
        "mailbox-acknowledge-01",
        owner.session_id,
        owner.session_secret,
        mailbox_id,
        acknowledgement_body.clone(),
    )
    .await?;
    assert_eq!(acknowledgement.status(), StatusCode::CREATED);
    assert_content_type(&acknowledgement, MAILBOX_ACK_RECEIPT_CONTENT_TYPE);
    let acknowledgement_receipt = response_bytes(acknowledgement).await?;
    let acknowledgement_replay = send_acknowledgement(
        app.clone(),
        "mailbox-acknowledge-01",
        owner.session_id,
        owner.session_secret,
        mailbox_id,
        acknowledgement_body.clone(),
    )
    .await?;
    assert_eq!(acknowledgement_replay.status(), StatusCode::OK);
    assert_eq!(
        response_bytes(acknowledgement_replay).await?,
        acknowledgement_receipt
    );

    let post_ack_pull = send_pull(
        app.clone(),
        owner.session_id,
        owner.session_secret,
        mailbox_id,
        mailbox_pull_body(SafeUint::new(0)?, 100)?,
    )
    .await?;
    assert_eq!(post_ack_pull.status(), StatusCode::OK);
    assert_empty_pull_receipt(&response_bytes(post_ack_pull).await?, mailbox_id)?;

    // The mailbox row lock must serialize concurrent senders.  Pre-seeding the
    // aggregate leaves exactly one remaining slot without fabricating opaque
    // envelope rows or bypassing the HTTP capability boundary.
    sqlx::query(
        "UPDATE messaging.mailboxes
            SET active_envelope_count=999, active_envelope_bytes=0
          WHERE mailbox_id=$1",
    )
    .bind(*mailbox_id.as_uuid())
    .execute(harness.admin_pool())
    .await?;
    let quota_left_id = EnvelopeId::new();
    let quota_right_id = EnvelopeId::new();
    let (quota_left, quota_right) = tokio::join!(
        send_envelope(
            app.clone(),
            "mailbox-quota-left-01",
            capability,
            mailbox_id,
            quota_left_id,
            mailbox_envelope_body(quota_left_id, &[0x01], UtcMillis::new(EXPIRY)?)?,
        ),
        send_envelope(
            app.clone(),
            "mailbox-quota-right01",
            capability,
            mailbox_id,
            quota_right_id,
            mailbox_envelope_body(quota_right_id, &[0x02], UtcMillis::new(EXPIRY)?)?,
        ),
    );
    let quota_left = quota_left?;
    let quota_right = quota_right?;
    let capacity_response = if quota_left.status() == StatusCode::CREATED {
        assert_eq!(quota_right.status(), StatusCode::TOO_MANY_REQUESTS);
        quota_right
    } else {
        assert_eq!(quota_left.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(quota_right.status(), StatusCode::CREATED);
        quota_left
    };
    assert_mailbox_error(
        capacity_response,
        StatusCode::TOO_MANY_REQUESTS,
        "MAILBOX_CAPACITY_EXCEEDED",
    )
    .await?;
    let active_envelopes: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM messaging.mailbox_envelopes
          WHERE mailbox_id=$1 AND state='available'",
    )
    .bind(*mailbox_id.as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(active_envelopes, 1);
    let aggregate: (i32, i64) = sqlx::query_as(
        "SELECT active_envelope_count, active_envelope_bytes
           FROM messaging.mailboxes
          WHERE mailbox_id=$1",
    )
    .bind(*mailbox_id.as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(aggregate, (1_000, 1));

    revoke_active_device(&identity_store, &owner).await?;
    let revoked_pull = send_pull(
        app.clone(),
        owner.session_id,
        owner.session_secret,
        mailbox_id,
        mailbox_pull_body(SafeUint::new(0)?, 1)?,
    )
    .await?;
    assert_mailbox_error(
        revoked_pull,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;
    let revoked_registration_replay = send_registration(
        app.clone(),
        "mailbox-register-0001",
        owner.session_id,
        owner.session_secret,
        mailbox_id,
        registration_body,
    )
    .await?;
    assert_mailbox_error(
        revoked_registration_replay,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;
    let revoked_ack_replay = send_acknowledgement(
        app,
        "mailbox-acknowledge-01",
        owner.session_id,
        owner.session_secret,
        mailbox_id,
        acknowledgement_body,
    )
    .await?;
    assert_mailbox_error(
        revoked_ack_replay,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;
    Ok(())
}

struct ActiveDevice {
    root: SigningKey,
    identity_id: IdentityId,
    device_id: DeviceId,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
}

async fn enroll_active_device(
    store: &IdentityPgStore,
    root_seed: u8,
    recovery_seed: u8,
    device_seed: u8,
    session_secret: [u8; 32],
) -> Result<ActiveDevice, Box<dyn Error>> {
    let root = SigningKey::from_bytes(&[root_seed; 32]);
    let recovery = SigningKey::from_bytes(&[recovery_seed; 32]);
    let device = SigningKey::from_bytes(&[device_seed; 32]);
    let genesis = genesis(&root, &recovery, 1_000)?;
    let identity_id = genesis.identity_id();
    let repository = IdentityLogRepository::new();
    let bootstrap = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-mailbox-bootstrap\0", &[root_seed]),
        None,
        genesis.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append_bootstrap(store, &bootstrap, UtcMillis::new(1_200)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
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
    assert!(matches!(
        repository
            .append_initial_device(
                store,
                Sha256Digest::hash_domain(b"test-mailbox-initial\0", &[root_seed]),
                genesis.entry_hash()?,
                initial.to_deterministic_cbor()?,
                UtcMillis::new(1_300)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let challenge = DeviceSessionRepository
        .issue_challenge(
            store,
            identity_id,
            device_id,
            [device_seed; 32],
            AUDIENCE,
            UtcMillis::new(NOW)?,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let proof = signature(
        &device,
        &device_session_proof_input(
            identity_id,
            device_id,
            challenge.challenge_id(),
            challenge.nonce(),
            AUDIENCE,
            session_id,
            session_secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    let completion = DeviceSessionCompletionCommand::new(
        Sha256Digest::hash_domain(b"test-mailbox-session\0", &[root_seed]),
        identity_id,
        device_id,
        challenge.challenge_id(),
        session_id,
        *challenge.nonce(),
        session_secret,
        proof,
    )?;
    assert!(matches!(
        DeviceSessionRepository
            .complete(store, &completion, UtcMillis::new(NOW)?)
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(ActiveDevice {
        root,
        identity_id,
        device_id,
        session_id,
        session_secret,
    })
}

async fn revoke_active_device(
    store: &IdentityPgStore,
    active: &ActiveDevice,
) -> Result<(), Box<dyn Error>> {
    let repository = IdentityLogRepository::new();
    let head = repository
        .load(store, active.identity_id)
        .await?
        .ok_or("identity log missing before mailbox owner revoke")?
        .head();
    let revoke = signed_event(
        &active.root,
        active.identity_id,
        head.sequence().get() + 1,
        Some(head.hash()),
        3_000,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: active.device_id,
        },
    )?;
    let command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(
            b"test-mailbox-revoke\0",
            active.device_id.to_string().as_bytes(),
        ),
        Some(head),
        revoke.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append(store, &command, UtcMillis::new(3_000)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    Ok(())
}

fn mailbox_registration_body(
    mailbox_id: MailboxId,
    owner_identity_id: IdentityId,
    owner_device_id: DeviceId,
    capability: [u8; 32],
    expires_at: UtcMillis,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let capability_hash =
        Sha256Digest::hash_domain(MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN, &capability);
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(mailbox_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(owner_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(owner_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            capability_hash.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(6), expires_at.to_canonical_value()),
    ]))?)
}

fn mailbox_envelope_body(
    envelope_id: EnvelopeId,
    opaque_ciphertext: &[u8],
    expires_at: UtcMillis,
) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(envelope_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Bytes(opaque_ciphertext.to_vec()),
        ),
        (CanonicalValue::Unsigned(4), expires_at.to_canonical_value()),
    ]))?)
}

fn mailbox_pull_body(after_sequence: SafeUint, limit: u16) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            after_sequence.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Unsigned(u64::from(limit)),
        ),
    ]))?)
}

fn mailbox_ack_body(envelope_ids: &[EnvelopeId]) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Array(
                envelope_ids
                    .iter()
                    .map(|id| CanonicalValue::Text(id.to_string()))
                    .collect(),
            ),
        ),
    ]))?)
}

async fn send_registration(
    app: axum::Router,
    idempotency_key: &str,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
    mailbox_id: MailboxId,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("PUT")
            .uri(MAILBOX_REGISTER_PATH_TEMPLATE.replace("{mailbox_id}", &mailbox_id.to_string()))
            .header(header::CONTENT_TYPE, MAILBOX_REGISTER_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(session_id, session_secret),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_envelope(
    app: axum::Router,
    idempotency_key: &str,
    capability: [u8; 32],
    mailbox_id: MailboxId,
    envelope_id: EnvelopeId,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("PUT")
            .uri(
                MAILBOX_ENQUEUE_PATH_TEMPLATE
                    .replace("{mailbox_id}", &mailbox_id.to_string())
                    .replace("{envelope_id}", &envelope_id.to_string()),
            )
            .header(header::CONTENT_TYPE, MAILBOX_ENVELOPE_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(
                header::AUTHORIZATION,
                mailbox_capability_authorization(capability),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_pull(
    app: axum::Router,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
    mailbox_id: MailboxId,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(MAILBOX_PULL_PATH_TEMPLATE.replace("{mailbox_id}", &mailbox_id.to_string()))
            .header(header::CONTENT_TYPE, MAILBOX_PULL_CONTENT_TYPE)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(session_id, session_secret),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_acknowledgement(
    app: axum::Router,
    idempotency_key: &str,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
    mailbox_id: MailboxId,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(MAILBOX_ACK_PATH_TEMPLATE.replace("{mailbox_id}", &mailbox_id.to_string()))
            .header(header::CONTENT_TYPE, MAILBOX_ACK_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(session_id, session_secret),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

fn device_session_authorization(session_id: DeviceSessionId, session_secret: [u8; 32]) -> String {
    format!(
        "{DEVICE_SESSION_AUTHORIZATION_SCHEME} {session_id}.{}",
        Base64UrlUnpadded::encode_string(&session_secret)
    )
}

fn mailbox_capability_authorization(capability: [u8; 32]) -> String {
    format!(
        "{MAILBOX_CAPABILITY_AUTHORIZATION_SCHEME} {}",
        Base64UrlUnpadded::encode_string(&capability)
    )
}

fn assert_content_type(response: &axum::response::Response, expected: &str) {
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(expected)
    );
}

async fn response_bytes(response: axum::response::Response) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(to_bytes(response.into_body(), 300_000).await?.to_vec())
}

async fn assert_mailbox_error(
    response: axum::response::Response,
    expected_status: StatusCode,
    expected_code: &str,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(response.status(), expected_status);
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
    let body: serde_json::Value = serde_json::from_slice(&response_bytes(response).await?)?;
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_str),
        Some(expected_code)
    );
    Ok(())
}

fn assert_pull_receipt(
    bytes: &[u8],
    mailbox_id: MailboxId,
    envelope_id: EnvelopeId,
    opaque_ciphertext: &[u8],
) -> Result<(), Box<dyn Error>> {
    let value = decode_deterministic_cbor(bytes)?;
    let CanonicalValue::Map(fields) = value else {
        return Err("mailbox pull receipt was not a map".into());
    };
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[1].1, CanonicalValue::Text(mailbox_id.to_string()));
    assert_eq!(fields[2].1, SafeUint::new(1)?.to_canonical_value());
    let CanonicalValue::Array(envelopes) = &fields[3].1 else {
        return Err("mailbox pull receipt envelopes were not an array".into());
    };
    assert_eq!(envelopes.len(), 1);
    let CanonicalValue::Map(envelope) = &envelopes[0] else {
        return Err("mailbox pull receipt envelope was not a map".into());
    };
    assert_eq!(envelope[1].1, CanonicalValue::Text(envelope_id.to_string()));
    assert_eq!(
        envelope[2].1,
        CanonicalValue::Bytes(opaque_ciphertext.to_vec())
    );
    Ok(())
}

fn assert_empty_pull_receipt(bytes: &[u8], mailbox_id: MailboxId) -> Result<(), Box<dyn Error>> {
    let value = decode_deterministic_cbor(bytes)?;
    let CanonicalValue::Map(fields) = value else {
        return Err("empty mailbox pull receipt was not a map".into());
    };
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[1].1, CanonicalValue::Text(mailbox_id.to_string()));
    assert_eq!(fields[2].1, SafeUint::new(1)?.to_canonical_value());
    assert_eq!(fields[3].1, CanonicalValue::Array(Vec::new()));
    Ok(())
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

#[allow(clippy::too_many_arguments)]
fn device_add(
    root: &SigningKey,
    device: &SigningKey,
    identity_id: IdentityId,
    device_id: DeviceId,
    previous_hash: Sha256Digest,
    sequence: u64,
    occurred_at: i64,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let root_key = public_key(root)?;
    let device_key = public_key(device)?;
    let certificate_unsigned = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        device_id,
        device_key,
        DeviceEncryptionPublicKey::try_from([7_u8; 32])?,
        root_key,
        UtcMillis::new(occurred_at - 1)?,
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
        identity_id,
        sequence,
        Some(previous_hash),
        occurred_at,
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
