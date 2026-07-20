#[path = "../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{
    error::Error,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{
    Clock, ClockError, DeviceEnrollmentChallengeId, DeviceId, DeviceSessionId, EnvelopeId,
    IdentityId, MailboxId,
};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IDENTITY_LOG_WIRE_VERSION,
    IdentityLogEventPayloadV1, IdentityLogEventV1, KeyAcceptancePurposeV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input, key_rotation_acceptance_input,
    recovery_rotation_authorization_input,
};
use dtx_identity_persistence::{
    CreateHistoryRecoveryRequestCommand, DEVICE_SESSION_SECRET_HASH_DOMAIN,
    DeviceEnrollmentApprovalCommand, DeviceEnrollmentCapability, DeviceEnrollmentRepository,
    DeviceSessionCompletionCommand, DeviceSessionCredential, DeviceSessionOutcome,
    DeviceSessionRepository, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogHead,
    IdentityLogRepository, IdentityPgStore, device_session_proof_input,
    history_recovery_request_signature_input, history_recovery_request_unsigned_canonical_bytes,
};
use dtx_mailbox::{
    AttachmentCapability, AttachmentCreate, AttachmentError, AttachmentManifest,
    AttachmentRepository, AttachmentStatus, MAILBOX_OPERATION_REPLAY_RETENTION_MILLIS,
    MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN, MAX_ACTIVE_ENVELOPE_BYTES, MAX_OPAQUE_CIPHERTEXT_BYTES,
    MailboxPersistenceError, MailboxPgStore, MailboxRegistrationCommand, MailboxRepository,
};
use dtx_mailbox_node::{
    ACCOUNT_READ_CURSOR_QUERY_V1_CONTENT_TYPE, ACCOUNT_READ_CURSOR_QUERY_V1_PATH,
    ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE, ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
    DEVICE_HISTORY_GRANT_RECEIPT_V2_CONTENT_TYPE, DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
    DEVICE_HISTORY_GRANT_V1_PATH, DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
    DEVICE_HISTORY_GRANT_V2_PATH, DEVICE_SESSION_AUTHORIZATION_SCHEME,
    IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE, IDENTITY_MAILBOX_ACK_V2_PATH,
    IDENTITY_MAILBOX_PULL_RECEIPT_V3_CONTENT_TYPE, IDENTITY_MAILBOX_PULL_V2_CONTENT_TYPE,
    IDENTITY_MAILBOX_PULL_V2_PATH, IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE, MAILBOX_ACK_CONTENT_TYPE,
    MAILBOX_ACK_PATH_TEMPLATE, MAILBOX_ACK_RECEIPT_CONTENT_TYPE,
    MAILBOX_CAPABILITY_AUTHORIZATION_SCHEME, MAILBOX_ENQUEUE_PATH_TEMPLATE,
    MAILBOX_ENVELOPE_CONTENT_TYPE, MAILBOX_ENVELOPE_RECEIPT_CONTENT_TYPE,
    MAILBOX_PULL_CONTENT_TYPE, MAILBOX_PULL_PATH_TEMPLATE, MAILBOX_PULL_RECEIPT_CONTENT_TYPE,
    MAILBOX_REGISTER_CONTENT_TYPE, MAILBOX_REGISTER_PATH_TEMPLATE,
    MAILBOX_REGISTER_RECEIPT_CONTENT_TYPE, MailboxNodeState, mailbox_router_with_state,
};
use dtx_realtime_sync::{
    HEARTBEAT_INTERVAL_MILLIS, InvalidationKind, LEASE_TTL_MILLIS, OUTBOX_CLAIM_TTL_MILLIS,
    RealtimeSyncError, RealtimeSyncStore, ReplayPage,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, postgres::PgConnectOptions};
use tower::ServiceExt;
use uuid::Uuid;

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
        mailbox_store.clone(),
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

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one boundary test keeps signed history authorization, two-device pull/ACK isolation, revocation, and ciphertext retention coherent"
)]
async fn identity_mailbox_v2_ack_is_isolated_per_authorized_device() -> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(NOW)),
    ));
    let owner = enroll_active_device(&identity_store, 101, 102, 103, [104; 32]).await?;
    let second = add_active_device(&identity_store, &owner, 105, [106; 32]).await?;

    let mailbox_id = MailboxId::new();
    let capability = [107; 32];
    let register_body = mailbox_registration_body(
        mailbox_id,
        owner.identity_id,
        owner.device_id,
        capability,
        UtcMillis::new(EXPIRY)?,
    )?;
    let register_command = MailboxRegistrationCommand::new(
        Sha256Digest::hash_domain(b"test-identity-mailbox-register-v2\0", b"register"),
        mailbox_id,
        owner.identity_id,
        owner.device_id,
        Sha256Digest::hash_domain(MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN, &capability),
        UtcMillis::new(EXPIRY)?,
        register_body,
    )?;
    assert!(
        !MailboxRepository
            .register(
                &mailbox_store,
                &DeviceSessionCredential::new(owner.session_id, owner.session_secret)?,
                &register_command,
                UtcMillis::new(NOW)?,
            )
            .await?
            .replayed()
    );
    let second_mailbox_id = MailboxId::new();
    assert_eq!(
        send_registration(
            app.clone(),
            "identity-mailbox-secondary-register-v2",
            second.session_id,
            second.session_secret,
            second_mailbox_id,
            mailbox_registration_body(
                second_mailbox_id,
                second.identity_id,
                second.device_id,
                [110; 32],
                UtcMillis::new(EXPIRY)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let pull_body = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
        (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
    ]))?;
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_PULL_V2_PATH,
            IDENTITY_MAILBOX_PULL_V2_CONTENT_TYPE,
            None,
            second.session_id,
            second.session_secret,
            pull_body.clone(),
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("identity-mailbox-secondary-unauthorized-ack"),
            second.session_id,
            second.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
                (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            ]))?,
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    let envelope_id = EnvelopeId::new();
    assert_eq!(
        send_envelope(
            app.clone(),
            "identity-mailbox-envelope-v2",
            capability,
            mailbox_id,
            envelope_id,
            mailbox_envelope_body(
                envelope_id,
                b"opaque-for-both-devices",
                UtcMillis::new(EXPIRY)?
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );

    let head_hash: Vec<u8> =
        sqlx::query_scalar("SELECT head_hash FROM identity.log_heads WHERE identity_id=$1")
            .bind(owner.identity_id.to_string())
            .fetch_one(harness.admin_pool())
            .await?;
    let unsigned_grant = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(owner.identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(second.device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Bytes(head_hash),
        ),
        (CanonicalValue::Unsigned(5), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Bytes(vec![108; 32]),
        ),
        (CanonicalValue::Unsigned(7), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(owner.device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Bytes(vec![109; 32]),
        ),
        (
            CanonicalValue::Unsigned(10),
            UtcMillis::new(NOW)?.to_canonical_value(),
        ),
    ]);
    let unsigned_bytes = encode_deterministic_cbor(&unsigned_grant)?;
    let mut grant_input = b"dirextalk.device-history-grant.v1\0".to_vec();
    grant_input.extend_from_slice(&unsigned_bytes);
    let mut pop_input = b"dirextalk.device-history-grant-pop.v1\0".to_vec();
    pop_input.extend_from_slice(&unsigned_bytes);
    let CanonicalValue::Map(mut grant_fields) = unsigned_grant else {
        unreachable!()
    };
    grant_fields.push((
        CanonicalValue::Unsigned(11),
        signature(&SigningKey::from_bytes(&[103; 32]), &grant_input).to_canonical_value(),
    ));
    grant_fields.push((
        CanonicalValue::Unsigned(12),
        signature(&SigningKey::from_bytes(&[105; 32]), &pop_input).to_canonical_value(),
    ));
    assert_eq!(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V1_PATH,
            DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
            None,
            owner.session_id,
            owner.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(grant_fields))?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );

    for device in [&owner, &second] {
        let pulled = send_v2(
            app.clone(),
            IDENTITY_MAILBOX_PULL_V2_PATH,
            IDENTITY_MAILBOX_PULL_V2_CONTENT_TYPE,
            None,
            device.session_id,
            device.session_secret,
            pull_body.clone(),
        )
        .await?;
        assert_eq!(pulled.status(), StatusCode::OK);
        let decoded = decode_deterministic_cbor(&response_bytes(pulled).await?)?;
        let CanonicalValue::Map(fields) = decoded else {
            return Err("V2 pull receipt not a map".into());
        };
        assert!(matches!(&fields[4].1, CanonicalValue::Array(entries) if entries.len()==1));
    }

    let ack_body = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(1)),
    ]))?;
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("identity-mailbox-owner-ack"),
            owner.session_id,
            owner.session_secret,
            ack_body.clone(),
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    let second_after_owner_ack = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V2_PATH,
        IDENTITY_MAILBOX_PULL_V2_CONTENT_TYPE,
        None,
        second.session_id,
        second.session_secret,
        pull_body,
    )
    .await?;
    let CanonicalValue::Map(fields) =
        decode_deterministic_cbor(&response_bytes(second_after_owner_ack).await?)?
    else {
        return Err("second V2 pull receipt not a map".into());
    };
    assert!(matches!(&fields[4].1, CanonicalValue::Array(entries) if entries.len()==1));
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("identity-mailbox-second-ack"),
            second.session_id,
            second.session_secret,
            ack_body,
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    let states: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT device_id,contiguous_ack_sequence FROM messaging.device_delivery_state
          WHERE identity_id=$1 ORDER BY device_id",
    )
    .bind(owner.identity_id.to_string())
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(states.len(), 2);
    assert!(states.iter().all(|(_, cursor)| *cursor == 1));
    let retained: Vec<u8> = sqlx::query_scalar(
        "SELECT opaque_ciphertext FROM messaging.mailbox_envelopes WHERE mailbox_id=$1 AND envelope_id=$2",
    ).bind(*mailbox_id.as_uuid()).bind(*envelope_id.as_uuid()).fetch_one(harness.admin_pool()).await?;
    assert_eq!(retained, b"opaque-for-both-devices");
    revoke_active_device(&identity_store, &owner).await?;
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_PULL_V2_PATH,
            IDENTITY_MAILBOX_PULL_V2_CONTENT_TYPE,
            None,
            second.session_id,
            second.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
                (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
                (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
            ]))?,
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    assert_eq!(
        send_v2(
            app,
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("identity-mailbox-second-ack-after-grantor-revoke"),
            second.session_id,
            second.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
                (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(1)),
            ]))?,
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one V39 boundary proves expired prefix/interior terminal ranges and independent two-device advancement"
)]
async fn identity_mailbox_v3_advances_two_devices_across_expired_delivery_gaps()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let write_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(NOW)),
    ));
    let owner = enroll_active_device(&identity_store, 201, 202, 203, [204; 32]).await?;
    let second = add_active_device(&identity_store, &owner, 205, [206; 32]).await?;
    let mailbox_id = MailboxId::new();
    let capability = [207; 32];
    assert_eq!(
        send_registration(
            write_app.clone(),
            "v3-gap-register-0001",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_registration_body(
                mailbox_id,
                owner.identity_id,
                owner.device_id,
                capability,
                UtcMillis::new(EXPIRY)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let mut envelope_ids = Vec::new();
    for (index, expiry, ciphertext) in [
        (1_u8, NOW + 10, b"expired-prefix".as_slice()),
        (2, EXPIRY, b"live-before-gap".as_slice()),
        (3, NOW + 10, b"expired-interior".as_slice()),
        (4, EXPIRY, b"live-after-gap".as_slice()),
    ] {
        let envelope_id = EnvelopeId::new();
        envelope_ids.push(envelope_id);
        assert_eq!(
            send_envelope(
                write_app.clone(),
                &format!("v3-gap-envelope-{index}"),
                capability,
                mailbox_id,
                envelope_id,
                mailbox_envelope_body(envelope_id, ciphertext, UtcMillis::new(expiry)?)?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
    }
    // A Pull V3 page must never observe a journal row above the head captured
    // for its receipt, even if a writer becomes visible between those reads.
    sqlx::query(
        "UPDATE messaging.identity_delivery_heads SET next_sequence=3 WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .execute(harness.admin_pool())
    .await?;
    let captured = send_v2(
        write_app.clone(),
        IDENTITY_MAILBOX_PULL_V2_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        owner.session_id,
        owner.session_secret,
        encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
            (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
        ]))?,
    )
    .await?;
    assert_eq!(captured.status(), StatusCode::OK);
    let CanonicalValue::Map(captured_fields) =
        decode_deterministic_cbor(&response_bytes(captured).await?)?
    else {
        return Err("captured V3 pull receipt not a map".into());
    };
    assert_eq!(captured_fields[3].1, CanonicalValue::Unsigned(3));
    assert!(matches!(&captured_fields[5].1, CanonicalValue::Array(segments) if segments.len()==3));
    sqlx::query(
        "UPDATE messaging.identity_delivery_heads SET next_sequence=4 WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .execute(harness.admin_pool())
    .await?;
    let head = Sha256Digest::from_bytes(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT head_hash FROM identity.log_heads WHERE identity_id=$1",
        )
        .bind(owner.identity_id.to_string())
        .fetch_one(harness.admin_pool())
        .await?
        .try_into()
        .map_err(|_| "identity head digest size")?,
    );
    assert_eq!(
        send_v2(
            write_app,
            DEVICE_HISTORY_GRANT_V1_PATH,
            DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
            None,
            owner.session_id,
            owner.session_secret,
            device_history_grant_body(
                owner.identity_id,
                second.device_id,
                head,
                1,
                owner.device_id.to_string(),
                &SigningKey::from_bytes(&[203; 32]),
                &SigningKey::from_bytes(&[205; 32]),
                208,
                209,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let resume_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(NOW + 20)),
    ));
    let request = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
        (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
    ]))?;
    for (index, device) in [&owner, &second].into_iter().enumerate() {
        let response = send_v2(
            resume_app.clone(),
            IDENTITY_MAILBOX_PULL_V2_PATH,
            IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
            None,
            device.session_id,
            device.session_secret,
            request.clone(),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_content_type(&response, IDENTITY_MAILBOX_PULL_RECEIPT_V3_CONTENT_TYPE);
        let bytes = response_bytes(response).await?;
        assert!(
            !bytes
                .windows(b"expired-prefix".len())
                .any(|window| window == b"expired-prefix")
        );
        assert!(
            !bytes
                .windows(b"expired-interior".len())
                .any(|window| window == b"expired-interior")
        );
        let CanonicalValue::Map(fields) = decode_deterministic_cbor(&bytes)? else {
            return Err("V3 pull receipt not a map".into());
        };
        assert_eq!(fields[3].1, CanonicalValue::Unsigned(4));
        assert_eq!(fields[4].1, CanonicalValue::Unsigned(0));
        let CanonicalValue::Array(segments) = &fields[5].1 else {
            return Err("V3 pull segments missing".into());
        };
        assert_eq!(segments.len(), 4);
        let expected = [(2_u64, 1_u64, 1_u64), (1, 2, 0), (2, 3, 3), (1, 4, 0)];
        for (segment, (kind, first, last)) in segments.iter().zip(expected) {
            let CanonicalValue::Map(segment) = segment else {
                return Err("V3 pull segment not a map".into());
            };
            assert_eq!(segment[0].1, CanonicalValue::Unsigned(kind));
            assert_eq!(segment[1].1, CanonicalValue::Unsigned(first));
            if last != 0 {
                assert_eq!(segment[2].1, CanonicalValue::Unsigned(last));
            }
        }
        assert_eq!(
            send_v2(
                resume_app.clone(),
                IDENTITY_MAILBOX_ACK_V2_PATH,
                IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
                Some(if index == 0 {
                    "v3-owner-ack-0001"
                } else {
                    "v3-second-ack-0001"
                }),
                device.session_id,
                device.session_secret,
                encode_deterministic_cbor(&CanonicalValue::Map(vec![
                    (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
                    (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(4)),
                ]))?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
    }
    let states: Vec<i64> = sqlx::query_scalar(
        "SELECT contiguous_ack_sequence FROM messaging.device_delivery_state
          WHERE identity_id=$1 ORDER BY device_id",
    )
    .bind(owner.identity_id.to_string())
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(states, vec![4, 4]);
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL boundary covers retained-byte quota, exact replay, and bounded post-horizon metadata GC"
)]
async fn retained_mailbox_quota_and_replay_metadata_are_horizon_bounded()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 6).await?;
    let realtime_store =
        RealtimeSyncStore::connect(harness.realtime_sync_runtime_options(), 4).await?;
    let database_now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;

    // ACK changes delivery state only. Even after logical expiry, every
    // non-null ciphertext remains charged until a durable tombstone exists.
    let quota_now = database_now - 100;
    let quota_owner =
        enroll_active_device_at(&identity_store, 231, 232, 233, [234; 32], quota_now).await?;
    let quota_mailbox = MailboxId::new();
    let quota_capability = [235; 32];
    let quota_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(quota_now)),
    ));
    assert_eq!(
        send_registration(
            quota_app.clone(),
            "retained-quota-register-0001",
            quota_owner.session_id,
            quota_owner.session_secret,
            quota_mailbox,
            mailbox_registration_body(
                quota_mailbox,
                quota_owner.identity_id,
                quota_owner.device_id,
                quota_capability,
                UtcMillis::new(quota_now + 600_000)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let mut ack_batch = Vec::new();
    for index in 0..(MAX_ACTIVE_ENVELOPE_BYTES / MAX_OPAQUE_CIPHERTEXT_BYTES) {
        let envelope_id = EnvelopeId::new();
        ack_batch.push(envelope_id);
        assert_eq!(
            send_envelope(
                quota_app.clone(),
                &format!("retained-quota-envelope-{index:04}"),
                quota_capability,
                quota_mailbox,
                envelope_id,
                mailbox_envelope_body(
                    envelope_id,
                    &vec![0x71; MAX_OPAQUE_CIPHERTEXT_BYTES],
                    UtcMillis::new(quota_now + 60_000)?,
                )?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
        if ack_batch.len() == 100
            || index + 1 == MAX_ACTIVE_ENVELOPE_BYTES / MAX_OPAQUE_CIPHERTEXT_BYTES
        {
            assert_eq!(
                send_acknowledgement(
                    quota_app.clone(),
                    &format!("retained-quota-ack-{index:04}"),
                    quota_owner.session_id,
                    quota_owner.session_secret,
                    quota_mailbox,
                    mailbox_ack_body(&ack_batch)?,
                )
                .await?
                .status(),
                StatusCode::CREATED,
            );
            ack_batch.clear();
        }
    }
    let quota_facts: (i64, i64, i32, i64, i64) = sqlx::query_as(
        "SELECT count(*),COALESCE(sum(octet_length(opaque_ciphertext)),0)::bigint,
                mailbox.active_envelope_count,mailbox.active_envelope_bytes,
                (SELECT count(*) FROM messaging.identity_delivery_journal WHERE identity_id=$2)
           FROM messaging.mailbox_envelopes AS envelope
           JOIN messaging.mailboxes AS mailbox USING(mailbox_id)
          WHERE envelope.mailbox_id=$1 AND envelope.opaque_ciphertext IS NOT NULL
          GROUP BY mailbox.active_envelope_count,mailbox.active_envelope_bytes",
    )
    .bind(*quota_mailbox.as_uuid())
    .bind(quota_owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(
        quota_facts,
        (256, i64::try_from(MAX_ACTIVE_ENVELOPE_BYTES)?, 0, 0, 256,)
    );
    let refill_id = EnvelopeId::new();
    let denied_refill = send_envelope(
        mailbox_router_with_state(MailboxNodeState::with_clock(
            mailbox_store.clone(),
            Arc::new(FixedClock(quota_now + 60_001)),
        )),
        "retained-quota-refill-denied",
        quota_capability,
        quota_mailbox,
        refill_id,
        mailbox_envelope_body(
            refill_id,
            b"still-over-retained-cap",
            UtcMillis::new(quota_now + 120_000)?,
        )?,
    )
    .await?;
    assert_mailbox_error(
        denied_refill,
        StatusCode::TOO_MANY_REQUESTS,
        "MAILBOX_CAPACITY_EXCEEDED",
    )
    .await?;

    // A tombstoned enqueue retains its exact replay facts until the explicit
    // horizon, including its delivery row used by V39 terminal recovery.
    let replay_now = database_now - MAILBOX_OPERATION_REPLAY_RETENTION_MILLIS / 2;
    let replay_owner =
        enroll_active_device_at(&identity_store, 236, 237, 238, [239; 32], replay_now).await?;
    let replay_mailbox = MailboxId::new();
    let replay_capability = [240; 32];
    let replay_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(replay_now)),
    ));
    assert_eq!(
        send_registration(
            replay_app.clone(),
            "retained-replay-register-0001",
            replay_owner.session_id,
            replay_owner.session_secret,
            replay_mailbox,
            mailbox_registration_body(
                replay_mailbox,
                replay_owner.identity_id,
                replay_owner.device_id,
                replay_capability,
                UtcMillis::new(replay_now + 600_000)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let replay_envelope = EnvelopeId::new();
    let replay_body = mailbox_envelope_body(
        replay_envelope,
        b"exact-replay-within-horizon",
        UtcMillis::new(replay_now + 1)?,
    )?;
    let first = send_envelope(
        replay_app.clone(),
        "retained-replay-envelope-0001",
        replay_capability,
        replay_mailbox,
        replay_envelope,
        replay_body.clone(),
    )
    .await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    let exact_receipt = response_bytes(first).await?;
    let replay_ack_body = mailbox_ack_body(&[replay_envelope])?;
    let replay_ack = send_acknowledgement(
        replay_app.clone(),
        "retained-replay-legacy-ack-0001",
        replay_owner.session_id,
        replay_owner.session_secret,
        replay_mailbox,
        replay_ack_body.clone(),
    )
    .await?;
    assert_eq!(replay_ack.status(), StatusCode::CREATED);
    let exact_ack_receipt = response_bytes(replay_ack).await?;
    assert_eq!(
        send_v2(
            replay_app.clone(),
            IDENTITY_MAILBOX_PULL_V2_PATH,
            IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
            None,
            replay_owner.session_id,
            replay_owner.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
                (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
                (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
            ]))?,
        )
        .await?
        .status(),
        StatusCode::OK,
    );
    let replay_device_ack_body = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(1)),
    ]))?;
    let replay_device_ack = send_v2(
        replay_app.clone(),
        IDENTITY_MAILBOX_ACK_V2_PATH,
        IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
        Some("retained-replay-device-ack-0001"),
        replay_owner.session_id,
        replay_owner.session_secret,
        replay_device_ack_body.clone(),
    )
    .await?;
    assert_eq!(replay_device_ack.status(), StatusCode::CREATED);
    let exact_device_ack_receipt = response_bytes(replay_device_ack).await?;
    realtime_store
        .compact_expired(UtcMillis::new(database_now)?)
        .await?;
    let retained_replay: (String, bool, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT state,opaque_ciphertext IS NULL,
                (SELECT count(*) FROM messaging.mailbox_enqueue_claims WHERE mailbox_id=$1),
                (SELECT count(*) FROM messaging.identity_delivery_journal WHERE identity_id=$2),
                (SELECT compacted_through FROM messaging.identity_delivery_heads WHERE identity_id=$2),
                (SELECT count(*) FROM messaging.mailbox_ack_claims WHERE mailbox_id=$1),
                (SELECT count(*) FROM messaging.device_delivery_ack_claims WHERE identity_id=$2)
           FROM messaging.mailbox_envelopes WHERE mailbox_id=$1 AND envelope_id=$3",
    )
    .bind(*replay_mailbox.as_uuid())
    .bind(replay_owner.identity_id.to_string())
    .bind(*replay_envelope.as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(retained_replay, ("expired".to_owned(), true, 1, 1, 0, 1, 1));
    let replayed = send_envelope(
        mailbox_router_with_state(MailboxNodeState::with_clock(
            mailbox_store.clone(),
            Arc::new(FixedClock(replay_now + 2)),
        )),
        "retained-replay-envelope-0001",
        replay_capability,
        replay_mailbox,
        replay_envelope,
        replay_body,
    )
    .await?;
    assert_eq!(replayed.status(), StatusCode::OK);
    assert_eq!(response_bytes(replayed).await?, exact_receipt);
    let replayed_ack = send_acknowledgement(
        replay_app.clone(),
        "retained-replay-legacy-ack-0001",
        replay_owner.session_id,
        replay_owner.session_secret,
        replay_mailbox,
        replay_ack_body,
    )
    .await?;
    assert_eq!(replayed_ack.status(), StatusCode::OK);
    assert_eq!(response_bytes(replayed_ack).await?, exact_ack_receipt);
    let replayed_device_ack = send_v2(
        replay_app,
        IDENTITY_MAILBOX_ACK_V2_PATH,
        IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
        Some("retained-replay-device-ack-0001"),
        replay_owner.session_id,
        replay_owner.session_secret,
        replay_device_ack_body,
    )
    .await?;
    assert_eq!(replayed_device_ack.status(), StatusCode::OK);
    assert_eq!(
        response_bytes(replayed_device_ack).await?,
        exact_device_ack_receipt
    );

    // Old short-TTL cycles are fully collected in bounded passes, so rows and
    // idempotency claims converge instead of growing with every refill.
    let gc_now = database_now - MAILBOX_OPERATION_REPLAY_RETENTION_MILLIS - 10_000;
    let gc_owner =
        enroll_active_device_at(&identity_store, 241, 242, 243, [244; 32], gc_now).await?;
    let gc_mailbox = MailboxId::new();
    let gc_capability = [245; 32];
    let gc_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(gc_now)),
    ));
    assert_eq!(
        send_registration(
            gc_app.clone(),
            "retained-gc-register-0001",
            gc_owner.session_id,
            gc_owner.session_secret,
            gc_mailbox,
            mailbox_registration_body(
                gc_mailbox,
                gc_owner.identity_id,
                gc_owner.device_id,
                gc_capability,
                UtcMillis::new(gc_now + 600_000)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    for index in 0_i64..4 {
        let envelope_id = EnvelopeId::new();
        assert_eq!(
            send_envelope(
                gc_app.clone(),
                &format!("retained-gc-envelope-{index:04}"),
                gc_capability,
                gc_mailbox,
                envelope_id,
                mailbox_envelope_body(
                    envelope_id,
                    b"bounded-old-cycle",
                    UtcMillis::new(gc_now + index + 1)?,
                )?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
        let acknowledgement_body = mailbox_ack_body(&[envelope_id])?;
        for replay in 0..2 {
            assert_eq!(
                send_acknowledgement(
                    gc_app.clone(),
                    &format!("retained-gc-legacy-ack-{index:04}-{replay}"),
                    gc_owner.session_id,
                    gc_owner.session_secret,
                    gc_mailbox,
                    acknowledgement_body.clone(),
                )
                .await?
                .status(),
                StatusCode::CREATED,
            );
        }
        assert_eq!(
            send_v2(
                gc_app.clone(),
                IDENTITY_MAILBOX_PULL_V2_PATH,
                IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
                None,
                gc_owner.session_id,
                gc_owner.session_secret,
                encode_deterministic_cbor(&CanonicalValue::Map(vec![
                    (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
                    (
                        CanonicalValue::Unsigned(2),
                        CanonicalValue::Unsigned(u64::try_from(index)?),
                    ),
                    (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
                ]))?,
            )
            .await?
            .status(),
            StatusCode::OK,
        );
        let device_ack_body = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Unsigned(u64::try_from(index + 1)?),
            ),
        ]))?;
        for replay in 0..2 {
            assert_eq!(
                send_v2(
                    gc_app.clone(),
                    IDENTITY_MAILBOX_ACK_V2_PATH,
                    IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
                    Some(&format!("retained-gc-device-ack-{index:04}-{replay}")),
                    gc_owner.session_id,
                    gc_owner.session_secret,
                    device_ack_body.clone(),
                )
                .await?
                .status(),
                StatusCode::CREATED,
            );
        }
        realtime_store
            .compact_expired(UtcMillis::new(database_now)?)
            .await?;
        let bounded: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                (SELECT count(*) FROM messaging.mailbox_envelopes WHERE mailbox_id=$1),
                (SELECT count(*) FROM messaging.mailbox_enqueue_claims WHERE mailbox_id=$1),
                (SELECT count(*) FROM messaging.identity_delivery_journal WHERE identity_id=$2),
                (SELECT count(*) FROM messaging.mailbox_ack_claims WHERE mailbox_id=$1),
                (SELECT count(*) FROM messaging.device_delivery_ack_claims WHERE identity_id=$2),
                (SELECT count(*) FROM messaging.device_delivery_state WHERE identity_id=$2)",
        )
        .bind(*gc_mailbox.as_uuid())
        .bind(gc_owner.identity_id.to_string())
        .fetch_one(harness.admin_pool())
        .await?;
        assert_eq!(bounded, (0, 0, 0, 0, 0, 1));
    }
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL boundary test keeps bounded expiry refill, ACK independence, and append/compaction serialization coherent"
)]
async fn expired_delivery_compaction_is_bounded_and_concurrent_append_safe()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 6).await?;
    let realtime_store =
        RealtimeSyncStore::connect(harness.realtime_sync_runtime_options(), 4).await?;
    let base = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let owner = enroll_active_device_at(&identity_store, 211, 212, 213, [214; 32], base).await?;
    let mailbox_id = MailboxId::new();
    let capability = [215; 32];
    let register_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(base)),
    ));
    assert_eq!(
        send_registration(
            register_app,
            "retention-register-0001",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_registration_body(
                mailbox_id,
                owner.identity_id,
                owner.device_id,
                capability,
                UtcMillis::new(base + 600_000)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );

    // Repeated short-TTL refill releases quota only after the old ciphertext
    // is irreversibly tombstoned. Delivery and enqueue replay rows remain until
    // the explicit horizon, so a refill cannot erase a recent terminal fact.
    for index in 0_i64..4 {
        let now = base + index * 3;
        let envelope_id = EnvelopeId::new();
        let app = mailbox_router_with_state(MailboxNodeState::with_clock(
            mailbox_store.clone(),
            Arc::new(FixedClock(now)),
        ));
        assert_eq!(
            send_envelope(
                app,
                &format!("retention-refill-{index:04}"),
                capability,
                mailbox_id,
                envelope_id,
                mailbox_envelope_body(envelope_id, &[0x70; 4096], UtcMillis::new(now + 1)?)?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
        realtime_store
            .compact_expired(UtcMillis::new(now + 2)?)
            .await?;
        let bounded: (i64, i64, i64, i64, i32, i64) = sqlx::query_as(
            "SELECT
                (SELECT count(*) FROM messaging.mailbox_envelopes
                  WHERE mailbox_id=$1 AND opaque_ciphertext IS NOT NULL),
                (SELECT count(*) FROM messaging.identity_delivery_journal WHERE identity_id=$2),
                (SELECT compacted_through FROM messaging.identity_delivery_heads WHERE identity_id=$2),
                (SELECT count(*) FROM messaging.mailbox_enqueue_claims WHERE mailbox_id=$1),
                active_envelope_count,active_envelope_bytes
               FROM messaging.mailboxes WHERE mailbox_id=$1",
        )
        .bind(*mailbox_id.as_uuid())
        .bind(owner.identity_id.to_string())
        .fetch_one(harness.admin_pool())
        .await?;
        assert_eq!(bounded, (0, index + 1, 0, index + 1, 0, 0));
    }

    let expired_id = EnvelopeId::new();
    let race_now = base + 20;
    let race_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(race_now)),
    ));
    assert_eq!(
        send_envelope(
            race_app.clone(),
            "retention-race-expired",
            capability,
            mailbox_id,
            expired_id,
            mailbox_envelope_body(expired_id, b"expired-race", UtcMillis::new(race_now + 1)?)?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );

    let mut barrier_transaction = harness.admin_pool().begin().await?;
    sqlx::query("SELECT 1 FROM messaging.identity_delivery_heads WHERE identity_id=$1 FOR UPDATE")
        .bind(owner.identity_id.to_string())
        .execute(&mut *barrier_transaction)
        .await?;
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let compact_barrier = barrier.clone();
    let compact_store = realtime_store.clone();
    let compact_task = tokio::spawn(async move {
        compact_barrier.wait().await;
        compact_store
            .compact_expired(UtcMillis::new(race_now + 2).expect("valid compaction time"))
            .await
    });
    let append_barrier = barrier.clone();
    let live_id = EnvelopeId::new();
    let append_task = tokio::spawn(async move {
        append_barrier.wait().await;
        send_envelope(
            race_app,
            "retention-race-live",
            capability,
            mailbox_id,
            live_id,
            mailbox_envelope_body(
                live_id,
                b"live-after-race",
                UtcMillis::new(race_now + 60_000).expect("valid live expiry"),
            )
            .expect("valid live body"),
        )
        .await
        .expect("concurrent append response")
        .status()
    });
    barrier.wait().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    barrier_transaction.commit().await?;
    compact_task.await??;
    assert_eq!(append_task.await?, StatusCode::CREATED);

    let serialized: (i64, i64, i64) = sqlx::query_as(
        "SELECT next_sequence,compacted_through,
                (SELECT count(*) FROM messaging.identity_delivery_journal WHERE identity_id=$1)
           FROM messaging.identity_delivery_heads WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(serialized, (6, 0, 6));

    // A device ACK is only a device-local cursor fact. Before global expiry it
    // cannot tombstone ciphertext or remove the shared delivery row.
    assert_eq!(
        send_acknowledgement(
            mailbox_router_with_state(MailboxNodeState::with_clock(
                mailbox_store.clone(),
                Arc::new(FixedClock(race_now + 3)),
            )),
            "retention-race-ack",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_ack_body(&[live_id])?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    realtime_store
        .compact_expired(UtcMillis::new(race_now + 4)?)
        .await?;
    let retained: (String, bool, i64, i64) = sqlx::query_as(
        "SELECT state,opaque_ciphertext IS NOT NULL,
                (SELECT count(*) FROM messaging.identity_delivery_journal WHERE identity_id=$3),
                (SELECT count(*) FROM messaging.mailbox_envelopes
                  WHERE mailbox_id=$1 AND opaque_ciphertext IS NULL
                    AND octet_length(receipt_bytes)>0 AND octet_length(request_digest)=32)
           FROM messaging.mailbox_envelopes WHERE mailbox_id=$1 AND envelope_id=$2",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(*live_id.as_uuid())
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(retained, ("acked".to_owned(), true, 6, 5));
    let recovered = send_v2(
        mailbox_router_with_state(MailboxNodeState::with_clock(
            mailbox_store,
            Arc::new(FixedClock(race_now + 4)),
        )),
        IDENTITY_MAILBOX_PULL_V2_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        owner.session_id,
        owner.session_secret,
        encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
            (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
        ]))?,
    )
    .await?;
    assert_eq!(recovered.status(), StatusCode::OK);
    let CanonicalValue::Map(recovered_fields) =
        decode_deterministic_cbor(&response_bytes(recovered).await?)?
    else {
        return Err("compacted V3 pull receipt not a map".into());
    };
    assert_eq!(recovered_fields[3].1, CanonicalValue::Unsigned(6));
    let CanonicalValue::Array(recovered_segments) = &recovered_fields[5].1 else {
        return Err("compacted V3 pull segments missing".into());
    };
    assert_eq!(recovered_segments.len(), 2);
    assert!(matches!(
        &recovered_segments[0],
        CanonicalValue::Map(fields)
            if fields[0].1 == CanonicalValue::Unsigned(2)
                && fields[1].1 == CanonicalValue::Unsigned(1)
                && fields[2].1 == CanonicalValue::Unsigned(5)
    ));

    // Realtime append uses the same head-row barrier. A compactor racing a
    // committed append may remove only the expired prefix it actually saw;
    // it cannot advance the floor past the new live cursor.
    sqlx::query(
        "UPDATE realtime.journal SET created_at_ms=$2,expires_at_ms=$3 WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .bind(race_now)
    .bind(race_now + 5)
    .execute(harness.admin_pool())
    .await?;
    let before_realtime: i64 =
        sqlx::query_scalar("SELECT next_cursor FROM realtime.identity_heads WHERE identity_id=$1")
            .bind(owner.identity_id.to_string())
            .fetch_one(harness.admin_pool())
            .await?;
    let mut realtime_barrier_transaction = harness.admin_pool().begin().await?;
    sqlx::query("SELECT 1 FROM realtime.identity_heads WHERE identity_id=$1 FOR UPDATE")
        .bind(owner.identity_id.to_string())
        .execute(&mut *realtime_barrier_transaction)
        .await?;
    let realtime_barrier = Arc::new(tokio::sync::Barrier::new(3));
    let compact_barrier = realtime_barrier.clone();
    let compact_store = realtime_store.clone();
    let realtime_compact_task = tokio::spawn(async move {
        compact_barrier.wait().await;
        compact_store
            .compact_expired(UtcMillis::new(race_now + 6).expect("valid realtime compaction time"))
            .await
    });
    let append_barrier = realtime_barrier.clone();
    let append_pool = harness.admin_pool().clone();
    let append_identity = owner.identity_id.to_string();
    let realtime_append_task = tokio::spawn(async move {
        append_barrier.wait().await;
        let mut transaction = append_pool.begin().await?;
        let cursor: i64 = sqlx::query_scalar(
            "UPDATE realtime.identity_heads SET next_cursor=next_cursor+1
              WHERE identity_id=$1 RETURNING next_cursor",
        )
        .bind(&append_identity)
        .fetch_one(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO realtime.journal(
                 identity_id,cursor,event_kind,subject_digest,created_at_ms,expires_at_ms
             ) VALUES($1,$2,'durable_invalidation',$3,$4,$5)",
        )
        .bind(&append_identity)
        .bind(cursor)
        .bind(vec![0x72_u8; 32])
        .bind(race_now + 6)
        .bind(race_now + 60_000)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("INSERT INTO realtime.outbox(identity_id,cursor) VALUES($1,$2)")
            .bind(&append_identity)
            .bind(cursor)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok::<i64, sqlx::Error>(cursor)
    });
    realtime_barrier.wait().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    realtime_barrier_transaction.commit().await?;
    realtime_compact_task.await??;
    let appended_cursor = realtime_append_task.await??;
    assert_eq!(appended_cursor, before_realtime + 1);
    let realtime_serialized: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT next_cursor,journal_floor,
                (SELECT min(cursor) FROM realtime.journal WHERE identity_id=$1),
                (SELECT count(*) FROM realtime.journal WHERE identity_id=$1)
           FROM realtime.identity_heads WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(
        realtime_serialized,
        (appended_cursor, appended_cursor, appended_cursor, 1)
    );
    Ok(())
}

#[tokio::test]
async fn realtime_compactor_waits_for_writer_advisory_lock_before_realtime_head()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let database_now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let owner =
        enroll_active_device_at(&identity_store, 226, 227, 228, [229; 32], database_now).await?;
    let identity_id = owner.identity_id.to_string();

    let expired = sqlx::query(
        "UPDATE realtime.journal
            SET created_at_ms=$2,expires_at_ms=$3
          WHERE identity_id=$1",
    )
    .bind(&identity_id)
    .bind(database_now - 2)
    .bind(database_now - 1)
    .execute(harness.admin_pool())
    .await?;
    assert!(expired.rows_affected() > 0);
    sqlx::query(
        "INSERT INTO messaging.identity_delivery_heads(identity_id)
         VALUES($1) ON CONFLICT(identity_id) DO NOTHING",
    )
    .bind(&identity_id)
    .execute(harness.admin_pool())
    .await?;

    // Mirror the business writer's advisory -> messaging head -> realtime head
    // order. The compactor must wait at the advisory edge and must not retain a
    // realtime head lock while waiting, which was the former deadlock cycle.
    let mut writer = harness.admin_pool().begin().await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(
             hashtextextended('mailbox-identity:' || $1,0))",
    )
    .bind(&identity_id)
    .execute(&mut *writer)
    .await?;
    sqlx::query(
        "SELECT 1 FROM messaging.identity_delivery_heads
          WHERE identity_id=$1 FOR UPDATE",
    )
    .bind(&identity_id)
    .execute(&mut *writer)
    .await?;

    let mut compactor_connection =
        PgConnection::connect_with(&harness.realtime_sync_runtime_options()).await?;
    let compactor_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut compactor_connection)
        .await?;
    let compact_task = tokio::spawn(async move {
        sqlx::query_scalar::<_, i32>("SELECT realtime.compact_expired($1,256)")
            .bind(database_now)
            .fetch_one(&mut compactor_connection)
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let waiting_for_advisory: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                     SELECT 1 FROM pg_locks
                      WHERE pid=$1 AND locktype='advisory' AND NOT granted
                 )",
            )
            .bind(compactor_pid)
            .fetch_one(harness.admin_pool())
            .await?;
            if waiting_for_advisory {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "realtime compactor did not reach its advisory lock barrier")??;

    let realtime_head: i64 = sqlx::query_scalar(
        "SELECT next_cursor FROM realtime.identity_heads
          WHERE identity_id=$1 FOR UPDATE NOWAIT",
    )
    .bind(&identity_id)
    .fetch_one(&mut *writer)
    .await?;
    assert!(realtime_head > 0);
    writer.commit().await?;

    let compacted = compact_task.await??;
    assert!(compacted > 0);
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one clock-skew boundary keeps both accepted extremes and payload eligibility in one database"
)]
async fn mailbox_compaction_uses_database_clock_at_allowed_caller_skew()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let realtime_store =
        RealtimeSyncStore::connect(harness.realtime_sync_runtime_options(), 4).await?;
    let database_now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(harness.admin_pool())
            .await?;
    let write_now = database_now - 60_000;
    let owner =
        enroll_active_device_at(&identity_store, 241, 242, 243, [244; 32], write_now).await?;
    let mailbox_id = MailboxId::new();
    let capability = [245; 32];
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(write_now)),
    ));
    assert_eq!(
        send_registration(
            app.clone(),
            "database-clock-register-0001",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_registration_body(
                mailbox_id,
                owner.identity_id,
                owner.device_id,
                capability,
                UtcMillis::new(database_now + 600_000)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let expired_id = EnvelopeId::new();
    let future_id = EnvelopeId::new();
    for (idempotency_key, envelope_id, expires_at) in [
        ("database-clock-expired-0001", expired_id, database_now - 1),
        (
            "database-clock-future-0001",
            future_id,
            database_now + 30_000,
        ),
    ] {
        assert_eq!(
            send_envelope(
                app.clone(),
                idempotency_key,
                capability,
                mailbox_id,
                envelope_id,
                mailbox_envelope_body(
                    envelope_id,
                    b"database-clock-boundary",
                    UtcMillis::new(expires_at)?,
                )?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
    }

    let negative_skew_base: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(harness.admin_pool())
            .await?;
    realtime_store
        .compact_expired(UtcMillis::new(negative_skew_base - 55_000)?)
        .await?;
    let after_negative: Vec<(Uuid, String, bool)> = sqlx::query_as(
        "SELECT envelope_id,state,opaque_ciphertext IS NULL
           FROM messaging.mailbox_envelopes
          WHERE mailbox_id=$1 ORDER BY delivery_sequence",
    )
    .bind(*mailbox_id.as_uuid())
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(
        after_negative,
        vec![
            (*expired_id.as_uuid(), "expired".to_owned(), true),
            (*future_id.as_uuid(), "available".to_owned(), false),
        ]
    );

    let positive_skew_base: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(harness.admin_pool())
            .await?;
    realtime_store
        .compact_expired(UtcMillis::new(positive_skew_base + 55_000)?)
        .await?;
    let future_after_positive: (String, bool) = sqlx::query_as(
        "SELECT state,opaque_ciphertext IS NULL
           FROM messaging.mailbox_envelopes
          WHERE mailbox_id=$1 AND envelope_id=$2",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(*future_id.as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(future_after_positive, ("available".to_owned(), false));
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one boundary test binds current root/recovery authority, identity head, new-device PoP, and durable grant kind"
)]
async fn history_grants_accept_current_root_or_recovery_and_reject_stale_or_wrong_pop()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(NOW)),
    ));
    let owner = enroll_active_device(&identity_store, 121, 122, 123, [124; 32]).await?;
    let root_target = add_active_device(&identity_store, &owner, 125, [126; 32]).await?;
    let recovery_target = add_active_device(&identity_store, &owner, 127, [128; 32]).await?;
    let rejected_target = add_active_device(&identity_store, &owner, 129, [130; 32]).await?;
    let mailbox_id = MailboxId::new();
    assert_eq!(
        send_registration(
            app.clone(),
            "history-authority-register",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_registration_body(
                mailbox_id,
                owner.identity_id,
                owner.device_id,
                [131; 32],
                UtcMillis::new(EXPIRY)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let head = Sha256Digest::from_bytes(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT head_hash FROM identity.log_heads WHERE identity_id=$1",
        )
        .bind(owner.identity_id.to_string())
        .fetch_one(harness.admin_pool())
        .await?
        .try_into()
        .map_err(|_| "identity head digest size")?,
    );
    let root_id = Sha256Digest::hash_domain(
        b"dirextalk.device-history-authority-id.v1\0",
        SigningPublicKey::try_from(owner.root.verifying_key().to_bytes())?.as_bytes(),
    )
    .to_string();
    let recovery_id = Sha256Digest::hash_domain(
        b"dirextalk.device-history-authority-id.v1\0",
        SigningPublicKey::try_from(owner.recovery.verifying_key().to_bytes())?.as_bytes(),
    )
    .to_string();
    for (target, kind, id, signer, seed) in [
        (&root_target, 3, root_id, &owner.root, 132),
        (&recovery_target, 2, recovery_id, &owner.recovery, 133),
    ] {
        assert_eq!(
            send_v2(
                app.clone(),
                DEVICE_HISTORY_GRANT_V1_PATH,
                DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
                None,
                owner.session_id,
                owner.session_secret,
                device_history_grant_body(
                    owner.identity_id,
                    target.device_id,
                    head,
                    kind,
                    id,
                    signer,
                    &SigningKey::from_bytes(&[if kind == 3 { 125 } else { 127 }; 32]),
                    seed,
                    seed.wrapping_add(1),
                )?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
    }
    for (index, target) in [&root_target, &recovery_target].into_iter().enumerate() {
        let target_mailbox_id = MailboxId::new();
        assert_eq!(
            send_registration(
                app.clone(),
                &format!("history-authority-target-register-{index}"),
                target.session_id,
                target.session_secret,
                target_mailbox_id,
                mailbox_registration_body(
                    target_mailbox_id,
                    target.identity_id,
                    target.device_id,
                    [142_u8.wrapping_add(u8::try_from(index)?); 32],
                    UtcMillis::new(EXPIRY)?,
                )?,
            )
            .await?
            .status(),
            StatusCode::CREATED,
        );
        assert_eq!(
            send_v2(
                app.clone(),
                IDENTITY_MAILBOX_PULL_V2_PATH,
                IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
                None,
                target.session_id,
                target.session_secret,
                encode_deterministic_cbor(&CanonicalValue::Map(vec![
                    (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
                    (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
                    (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
                ]))?,
            )
            .await?
            .status(),
            StatusCode::OK,
        );
    }
    let authorities: Vec<(String, String)> = sqlx::query_as(
        "SELECT authorization_kind,authorizer_id FROM messaging.device_history_grants
          WHERE identity_id=$1 ORDER BY authorization_kind",
    )
    .bind(owner.identity_id.to_string())
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(
        authorities
            .iter()
            .map(|(kind, _)| kind.as_str())
            .collect::<Vec<_>>(),
        vec!["recovery", "root"]
    );
    assert!(authorities.iter().all(|(_, id)| id.starts_with("sha256:")));
    assert!(
        authorities
            .iter()
            .all(|(_, id)| !id.starts_with("ed25519:"))
    );

    let wrong_pop = device_history_grant_body(
        owner.identity_id,
        rejected_target.device_id,
        head,
        3,
        Sha256Digest::hash_domain(
            b"dirextalk.device-history-authority-id.v1\0",
            SigningPublicKey::try_from(owner.root.verifying_key().to_bytes())?.as_bytes(),
        )
        .to_string(),
        &owner.root,
        &owner.root,
        134,
        135,
    )?;
    assert_eq!(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V1_PATH,
            DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
            None,
            owner.session_id,
            owner.session_secret,
            wrong_pop,
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED,
    );
    let repository = IdentityLogRepository::new();
    let before_rotation = repository
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing before root rotation")?
        .head();
    let successor_root = SigningKey::from_bytes(&[138; 32]);
    let successor_public = public_key(&successor_root)?;
    let rotation = signed_event(
        &owner.root,
        owner.identity_id,
        before_rotation.sequence().get() + 1,
        Some(before_rotation.hash()),
        NOW,
        IdentityLogEventPayloadV1::RootRotate {
            new_root_signing_key: successor_public,
            acceptance_signature: signature(
                &successor_root,
                &key_rotation_acceptance_input(
                    owner.identity_id,
                    SafeUint::new(before_rotation.sequence().get() + 1)?,
                    Some(before_rotation.hash()),
                    KeyAcceptancePurposeV1::RootRotate,
                    successor_public,
                )?,
            ),
        },
    )?;
    assert!(matches!(
        repository
            .append(
                &identity_store,
                &IdentityAppendCommand::new(
                    Sha256Digest::hash_domain(b"test-mailbox-root-rotation\0", &[138]),
                    Some(before_rotation),
                    rotation.to_deterministic_cbor()?,
                )?,
                UtcMillis::new(NOW)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let key_change: (String, i64, i64) = sqlx::query_as(
        "SELECT journal.event_kind,journal.cursor,
                (SELECT count(*) FROM realtime.outbox AS pending
                  WHERE pending.identity_id=journal.identity_id AND pending.cursor=journal.cursor)
           FROM realtime.journal AS journal
          WHERE journal.identity_id=$1 ORDER BY journal.cursor DESC LIMIT 1",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(key_change.0, "key_authorization_changed");
    assert_eq!(key_change.2, 1);
    let after_rotation = repository
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing after root rotation")?
        .head();
    let root_after_rotation = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V2_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        root_target.session_id,
        root_target.session_secret,
        encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
            (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
        ]))?,
    )
    .await?;
    assert_eq!(root_after_rotation.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("history-root-target-ack-after-rotation"),
            root_target.session_id,
            root_target.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
                (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            ]))?,
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    let recovery_still_current = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V2_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        recovery_target.session_id,
        recovery_target.session_secret,
        encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
            (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
        ]))?,
    )
    .await?;
    assert_ne!(recovery_still_current.status(), StatusCode::NOT_FOUND);

    let successor_recovery = SigningKey::from_bytes(&[141; 32]);
    let successor_recovery_public = public_key(&successor_recovery)?;
    let recovery_sequence = SafeUint::new(after_rotation.sequence().get() + 1)?;
    let recovery_acceptance = signature(
        &successor_recovery,
        &key_rotation_acceptance_input(
            owner.identity_id,
            recovery_sequence,
            Some(after_rotation.hash()),
            KeyAcceptancePurposeV1::RecoveryRotate,
            successor_recovery_public,
        )?,
    );
    let recovery_rotation = signed_event(
        &successor_root,
        owner.identity_id,
        recovery_sequence.get(),
        Some(after_rotation.hash()),
        NOW,
        IdentityLogEventPayloadV1::RecoveryRotate {
            new_recovery_signing_key: successor_recovery_public,
            acceptance_signature: recovery_acceptance,
            recovery_authorization_signature: Some(signature(
                &owner.recovery,
                &recovery_rotation_authorization_input(
                    IDENTITY_LOG_WIRE_VERSION,
                    owner.identity_id,
                    recovery_sequence,
                    Some(after_rotation.hash()),
                    UtcMillis::new(NOW)?,
                    successor_public,
                    successor_recovery_public,
                    recovery_acceptance,
                )?,
            )),
        },
    )?;
    assert!(matches!(
        repository
            .append(
                &identity_store,
                &IdentityAppendCommand::new(
                    Sha256Digest::hash_domain(b"test-mailbox-recovery-rotation\0", &[141]),
                    Some(after_rotation),
                    recovery_rotation.to_deterministic_cbor()?,
                )?,
                UtcMillis::new(NOW)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let recovery_after_rotation = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V2_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        recovery_target.session_id,
        recovery_target.session_secret,
        encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
            (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
        ]))?,
    )
    .await?;
    assert_eq!(recovery_after_rotation.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("history-recovery-target-ack-after-rotation"),
            recovery_target.session_id,
            recovery_target.session_secret,
            encode_deterministic_cbor(&CanonicalValue::Map(vec![
                (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
                (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
            ]))?,
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    let revoked_old_root = device_history_grant_body(
        owner.identity_id,
        rejected_target.device_id,
        after_rotation.hash(),
        3,
        Sha256Digest::hash_domain(
            b"dirextalk.device-history-authority-id.v1\0",
            SigningPublicKey::try_from(owner.root.verifying_key().to_bytes())?.as_bytes(),
        )
        .to_string(),
        &owner.root,
        &SigningKey::from_bytes(&[129; 32]),
        139,
        140,
    )?;
    assert_eq!(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V1_PATH,
            DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
            None,
            owner.session_id,
            owner.session_secret,
            revoked_old_root,
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED,
    );
    let stale = device_history_grant_body(
        owner.identity_id,
        rejected_target.device_id,
        Sha256Digest::from_bytes([1; 32]),
        2,
        Sha256Digest::hash_domain(
            b"dirextalk.device-history-authority-id.v1\0",
            SigningPublicKey::try_from(owner.recovery.verifying_key().to_bytes())?.as_bytes(),
        )
        .to_string(),
        &owner.recovery,
        &SigningKey::from_bytes(&[129; 32]),
        136,
        137,
    )?;
    assert_eq!(
        send_v2(
            app,
            DEVICE_HISTORY_GRANT_V1_PATH,
            DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE,
            None,
            owner.session_id,
            owner.session_secret,
            stale,
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED,
    );
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one V40 HTTP/PostgreSQL boundary keeps approved-head, attachment, retained-quota, replay, expiry, and per-device cursor evidence coherent"
)]
async fn history_recovery_v2_offer_is_exact_current_and_device_ack_is_independent()
-> Result<(), Box<dyn Error>> {
    const PROVIDER_SEED: u8 = 151;
    const CANDIDATE_SEED: u8 = 155;
    const CANDIDATE_ENCRYPTION_SEED: u8 = 156;
    const GRANT_NOW: i64 = NOW + 20;
    const OFFER_EXPIRY: i64 = NOW + 120_000;
    const REQUEST_EXPIRY: i64 = NOW + 300_000;

    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 6).await?;
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(GRANT_NOW)),
    ));
    let owner = enroll_active_device(&identity_store, 152, 153, PROVIDER_SEED, [154; 32]).await?;
    let observed_head = IdentityLogRepository::new()
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing before V40 recovery request")?
        .head();
    let recovered = enroll_history_recovery_device(
        &identity_store,
        &owner,
        observed_head,
        CANDIDATE_SEED,
        CANDIDATE_ENCRYPTION_SEED,
        [157; 32],
        [158; 32],
        REQUEST_EXPIRY,
    )
    .await?;

    let mailbox_id = MailboxId::new();
    let mailbox_capability = [159; 32];
    assert_eq!(
        send_registration(
            app.clone(),
            "history-v2-register-0001",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_registration_body(
                mailbox_id,
                owner.identity_id,
                owner.device_id,
                mailbox_capability,
                UtcMillis::new(EXPIRY)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let pull_request = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(3)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
        (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
    ]))?;
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_PULL_V2_PATH,
            IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
            None,
            recovered.active.session_id,
            recovered.active.session_secret,
            pull_request.clone(),
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );

    let pre_grant_envelope = EnvelopeId::new();
    let pre_grant_ciphertext = b"opaque-pre-grant-history".to_vec();
    assert_eq!(
        send_envelope(
            app.clone(),
            "history-v2-pre-grant-envelope",
            mailbox_capability,
            mailbox_id,
            pre_grant_envelope,
            mailbox_envelope_body(
                pre_grant_envelope,
                &pre_grant_ciphertext,
                UtcMillis::new(OFFER_EXPIRY)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let provider_highwater: i64 = sqlx::query_scalar(
        "SELECT next_sequence FROM messaging.identity_delivery_heads WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(provider_highwater, 1);

    let (attachment_object_id, attachment_digest) = create_ready_history_attachment(
        &mailbox_store,
        &owner,
        160,
        UtcMillis::new(OFFER_EXPIRY)?,
        UtcMillis::new(GRANT_NOW - 3)?,
    )
    .await?;

    let authority_id = Sha256Digest::hash_domain(
        b"dirextalk.device-history-authority-id.v1\0",
        SigningPublicKey::try_from(owner.root.verifying_key().to_bytes())?.as_bytes(),
    )
    .to_string();
    let provider = SigningKey::from_bytes(&[PROVIDER_SEED; 32]);
    let stale_envelope = EnvelopeId::new();
    let stale_body = device_history_grant_body_v2(
        "history-v2-stale-head",
        owner.identity_id,
        recovered.request_id,
        recovered.request_digest,
        observed_head.hash(),
        recovered.active.device_id,
        owner.device_id,
        &authority_id,
        mailbox_id,
        stale_envelope,
        u64::try_from(provider_highwater)?,
        recovered.recipient_package_digest,
        attachment_digest,
        b"opaque-stale-head-offer",
        UtcMillis::new(GRANT_NOW)?,
        UtcMillis::new(OFFER_EXPIRY)?,
        &provider,
        &owner.root,
    )?;
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-stale-head"),
            owner.session_id,
            owner.session_secret,
            stale_body,
        )
        .await?,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;

    let missing_attachment_envelope = EnvelopeId::new();
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-missing-attachment"),
            owner.session_id,
            owner.session_secret,
            device_history_grant_body_v2(
                "history-v2-missing-attachment",
                owner.identity_id,
                recovered.request_id,
                recovered.request_digest,
                recovered.approved_head.hash(),
                recovered.active.device_id,
                owner.device_id,
                &authority_id,
                mailbox_id,
                missing_attachment_envelope,
                u64::try_from(provider_highwater)?,
                recovered.recipient_package_digest,
                Sha256Digest::from_bytes([162; 32]),
                b"opaque-missing-attachment-offer",
                UtcMillis::new(GRANT_NOW)?,
                UtcMillis::new(OFFER_EXPIRY)?,
                &provider,
                &owner.root,
            )?,
        )
        .await?,
        StatusCode::NOT_FOUND,
        "MAILBOX_UNAVAILABLE",
    )
    .await?;

    let overlong_envelope = EnvelopeId::new();
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-overlong-offer"),
            owner.session_id,
            owner.session_secret,
            device_history_grant_body_v2(
                "history-v2-overlong-offer",
                owner.identity_id,
                recovered.request_id,
                recovered.request_digest,
                recovered.approved_head.hash(),
                recovered.active.device_id,
                owner.device_id,
                &authority_id,
                mailbox_id,
                overlong_envelope,
                u64::try_from(provider_highwater)?,
                recovered.recipient_package_digest,
                attachment_digest,
                b"opaque-overlong-offer",
                UtcMillis::new(GRANT_NOW)?,
                UtcMillis::new(REQUEST_EXPIRY + 1)?,
                &provider,
                &owner.root,
            )?,
        )
        .await?,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;

    let expired_envelope = EnvelopeId::new();
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-expired-offer"),
            owner.session_id,
            owner.session_secret,
            device_history_grant_body_v2(
                "history-v2-expired-offer",
                owner.identity_id,
                recovered.request_id,
                recovered.request_digest,
                recovered.approved_head.hash(),
                recovered.active.device_id,
                owner.device_id,
                &authority_id,
                mailbox_id,
                expired_envelope,
                u64::try_from(provider_highwater)?,
                recovered.recipient_package_digest,
                attachment_digest,
                b"opaque-expired-offer",
                UtcMillis::new(GRANT_NOW - 1)?,
                UtcMillis::new(GRANT_NOW)?,
                &provider,
                &owner.root,
            )?,
        )
        .await?,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;

    let wrong_provider_envelope = EnvelopeId::new();
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-wrong-provider"),
            recovered.active.session_id,
            recovered.active.session_secret,
            device_history_grant_body_v2(
                "history-v2-wrong-provider",
                owner.identity_id,
                recovered.request_id,
                recovered.request_digest,
                recovered.approved_head.hash(),
                recovered.active.device_id,
                owner.device_id,
                &authority_id,
                mailbox_id,
                wrong_provider_envelope,
                u64::try_from(provider_highwater)?,
                recovered.recipient_package_digest,
                attachment_digest,
                b"opaque-wrong-provider-offer",
                UtcMillis::new(GRANT_NOW)?,
                UtcMillis::new(OFFER_EXPIRY)?,
                &provider,
                &owner.root,
            )?,
        )
        .await?,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;

    // Model 1,000 previously ACKed, still-retained legal ciphertext rows in a
    // separate registered mailbox. The live aggregate stays at zero, so this
    // specifically proves that a V40 offer is fenced by retained count rather
    // than the active counter without advancing the recovery delivery head.
    let quota_mailbox_id = MailboxId::new();
    assert_eq!(
        send_registration(
            app.clone(),
            "history-v2-quota-register-0001",
            owner.session_id,
            owner.session_secret,
            quota_mailbox_id,
            mailbox_registration_body(
                quota_mailbox_id,
                owner.identity_id,
                owner.device_id,
                [161; 32],
                UtcMillis::new(EXPIRY)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let quota_ids = (0..1_000).map(|_| Uuid::now_v7()).collect::<Vec<Uuid>>();
    let quota_sequences = (1_i64..=1_000).collect::<Vec<i64>>();
    sqlx::query(
        "INSERT INTO messaging.mailbox_envelopes(
             mailbox_id,envelope_id,delivery_sequence,opaque_ciphertext,request_digest,
             receipt_bytes,receipt_hash,expires_at_ms,state,created_at_ms)
         SELECT $1,item.envelope_id,item.delivery_sequence,$4,$5,$6,$7,$8,'acked',$9
           FROM unnest($2::uuid[],$3::bigint[]) AS item(envelope_id,delivery_sequence)",
    )
    .bind(*quota_mailbox_id.as_uuid())
    .bind(&quota_ids)
    .bind(&quota_sequences)
    .bind(vec![0xee_u8])
    .bind(vec![0xa1_u8; 32])
    .bind(vec![0xa2_u8])
    .bind(vec![0xa3_u8; 32])
    .bind(OFFER_EXPIRY)
    .bind(GRANT_NOW)
    .execute(harness.admin_pool())
    .await?;
    let retained_before_grant: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM messaging.mailbox_envelopes
          WHERE mailbox_id=$1 AND opaque_ciphertext IS NOT NULL",
    )
    .bind(*quota_mailbox_id.as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(retained_before_grant, 1_000);
    let quota_envelope = EnvelopeId::new();
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-retained-quota"),
            owner.session_id,
            owner.session_secret,
            device_history_grant_body_v2(
                "history-v2-retained-quota",
                owner.identity_id,
                recovered.request_id,
                recovered.request_digest,
                recovered.approved_head.hash(),
                recovered.active.device_id,
                owner.device_id,
                &authority_id,
                quota_mailbox_id,
                quota_envelope,
                u64::try_from(provider_highwater)?,
                recovered.recipient_package_digest,
                attachment_digest,
                b"opaque-retained-quota-offer",
                UtcMillis::new(GRANT_NOW)?,
                UtcMillis::new(OFFER_EXPIRY)?,
                &provider,
                &owner.root,
            )?,
        )
        .await?,
        StatusCode::TOO_MANY_REQUESTS,
        "MAILBOX_CAPACITY_EXCEEDED",
    )
    .await?;
    let offer_envelope = EnvelopeId::new();
    let opaque_offer = b"opaque-candidate-encrypted-history-offer".to_vec();
    let grant_body = device_history_grant_body_v2(
        "history-v2-success",
        owner.identity_id,
        recovered.request_id,
        recovered.request_digest,
        recovered.approved_head.hash(),
        recovered.active.device_id,
        owner.device_id,
        &authority_id,
        mailbox_id,
        offer_envelope,
        u64::try_from(provider_highwater)?,
        recovered.recipient_package_digest,
        attachment_digest,
        &opaque_offer,
        UtcMillis::new(GRANT_NOW)?,
        UtcMillis::new(OFFER_EXPIRY)?,
        &provider,
        &owner.root,
    )?;
    let granted = send_v2(
        app.clone(),
        DEVICE_HISTORY_GRANT_V2_PATH,
        DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
        Some("history-v2-success"),
        owner.session_id,
        owner.session_secret,
        grant_body.clone(),
    )
    .await?;
    assert_eq!(granted.status(), StatusCode::CREATED);
    assert_content_type(&granted, DEVICE_HISTORY_GRANT_RECEIPT_V2_CONTENT_TYPE);
    let exact_receipt = response_bytes(granted).await?;
    let replay = send_v2(
        app.clone(),
        DEVICE_HISTORY_GRANT_V2_PATH,
        DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
        Some("history-v2-success"),
        owner.session_id,
        owner.session_secret,
        grant_body,
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(replay).await?, exact_receipt);
    assert_mailbox_error(
        send_v2(
            app.clone(),
            DEVICE_HISTORY_GRANT_V2_PATH,
            DEVICE_HISTORY_GRANT_V2_CONTENT_TYPE,
            Some("history-v2-success"),
            owner.session_id,
            owner.session_secret,
            device_history_grant_body_v2(
                "history-v2-success",
                owner.identity_id,
                recovered.request_id,
                recovered.request_digest,
                recovered.approved_head.hash(),
                recovered.active.device_id,
                owner.device_id,
                &authority_id,
                mailbox_id,
                offer_envelope,
                u64::try_from(provider_highwater)?,
                recovered.recipient_package_digest,
                attachment_digest,
                b"changed-opaque-offer",
                UtcMillis::new(GRANT_NOW)?,
                UtcMillis::new(OFFER_EXPIRY)?,
                &provider,
                &owner.root,
            )?,
        )
        .await?,
        StatusCode::CONFLICT,
        "IDEMPOTENCY_CONFLICT",
    )
    .await?;

    let candidate_pull = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V2_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        recovered.active.session_id,
        recovered.active.session_secret,
        pull_request.clone(),
    )
    .await?;
    assert_eq!(candidate_pull.status(), StatusCode::OK);
    assert_content_type(
        &candidate_pull,
        IDENTITY_MAILBOX_PULL_RECEIPT_V3_CONTENT_TYPE,
    );
    assert_v3_single_envelope(
        &response_bytes(candidate_pull).await?,
        2,
        1,
        offer_envelope,
        &opaque_offer,
    )?;

    let owner_pull = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V2_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        owner.session_id,
        owner.session_secret,
        pull_request.clone(),
    )
    .await?;
    assert_eq!(owner_pull.status(), StatusCode::OK);
    let CanonicalValue::Map(owner_pull_fields) =
        decode_deterministic_cbor(&response_bytes(owner_pull).await?)?
    else {
        return Err("owner V3 pull receipt not a map".into());
    };
    assert!(
        matches!(&owner_pull_fields[5].1, CanonicalValue::Array(segments) if segments.len()==2)
    );
    let ack_two = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(2)),
    ]))?;
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("history-v2-owner-ack"),
            owner.session_id,
            owner.session_secret,
            ack_two.clone(),
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let candidate_after_owner_ack = send_v2(
        app.clone(),
        IDENTITY_MAILBOX_PULL_V2_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        recovered.active.session_id,
        recovered.active.session_secret,
        pull_request.clone(),
    )
    .await?;
    assert_eq!(candidate_after_owner_ack.status(), StatusCode::OK);
    assert_v3_single_envelope(
        &response_bytes(candidate_after_owner_ack).await?,
        2,
        1,
        offer_envelope,
        &opaque_offer,
    )?;
    assert_eq!(
        send_v2(
            app.clone(),
            IDENTITY_MAILBOX_ACK_V2_PATH,
            IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
            Some("history-v2-candidate-ack"),
            recovered.active.session_id,
            recovered.active.session_secret,
            ack_two,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let cursors: Vec<(Uuid, i64, i64)> = sqlx::query_as(
        "SELECT device_id,contiguous_ack_sequence,earliest_authorized_sequence
           FROM messaging.device_delivery_state WHERE identity_id=$1 ORDER BY device_id",
    )
    .bind(owner.identity_id.to_string())
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(cursors.len(), 2);
    assert!(cursors.iter().all(|(_, ack, _)| *ack == 2));
    assert!(
        cursors
            .iter()
            .any(|(device, _, floor)| { *device == Uuid::from(owner.device_id) && *floor == 1 })
    );
    assert!(cursors.iter().any(|(device, _, floor)| {
        *device == Uuid::from(recovered.active.device_id) && *floor == 2
    }));
    let retained: Vec<(Uuid, Vec<u8>)> = sqlx::query_as(
        "SELECT envelope_id,opaque_ciphertext FROM messaging.mailbox_envelopes
          WHERE mailbox_id=$1 ORDER BY delivery_sequence",
    )
    .bind(*mailbox_id.as_uuid())
    .fetch_all(harness.admin_pool())
    .await?;
    assert_eq!(retained.len(), 2);
    assert_eq!(retained[0].1, pre_grant_ciphertext);
    assert_eq!(retained[1].1, opaque_offer);

    assert_eq!(
        AttachmentRepository
            .cancel(
                &mailbox_store,
                &DeviceSessionCredential::new(owner.session_id, owner.session_secret)?,
                attachment_object_id,
                UtcMillis::new(GRANT_NOW + 1)?,
            )
            .await
            .unwrap(),
        AttachmentStatus::Cancelled,
    );
    let cancelled_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(GRANT_NOW + 1)),
    ));
    assert_eq!(
        send_v2(
            cancelled_app,
            IDENTITY_MAILBOX_PULL_V2_PATH,
            IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
            None,
            recovered.active.session_id,
            recovered.active.session_secret,
            pull_request.clone(),
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    let (_, replacement_digest) = create_ready_history_attachment(
        &mailbox_store,
        &owner,
        165,
        UtcMillis::new(OFFER_EXPIRY)?,
        UtcMillis::new(GRANT_NOW + 2)?,
    )
    .await?;
    assert_eq!(replacement_digest, attachment_digest);
    let restored_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(GRANT_NOW + 5)),
    ));
    let restored_pull = send_v2(
        restored_app,
        IDENTITY_MAILBOX_PULL_V2_PATH,
        IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
        None,
        recovered.active.session_id,
        recovered.active.session_secret,
        pull_request.clone(),
    )
    .await?;
    assert_eq!(restored_pull.status(), StatusCode::OK);
    assert_v3_single_envelope(
        &response_bytes(restored_pull).await?,
        2,
        1,
        offer_envelope,
        &opaque_offer,
    )?;

    let next_device = SigningKey::from_bytes(&[163; 32]);
    let current_head = IdentityLogRepository::new()
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing before stale-offer fence")?
        .head();
    let next_event = device_add(
        &owner.root,
        &next_device,
        owner.identity_id,
        DeviceId::new(),
        164,
        current_head.hash(),
        current_head.sequence().get() + 1,
        GRANT_NOW + 10,
    )?;
    assert!(matches!(
        IdentityLogRepository::new()
            .append(
                &identity_store,
                &IdentityAppendCommand::new(
                    Sha256Digest::hash_domain(b"test-history-v2-advance-head\0", &[164]),
                    Some(current_head),
                    next_event.to_deterministic_cbor()?,
                )?,
                UtcMillis::new(GRANT_NOW + 10)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    assert_eq!(
        send_v2(
            mailbox_router_with_state(MailboxNodeState::with_clock(
                mailbox_store,
                Arc::new(FixedClock(GRANT_NOW + 11)),
            )),
            IDENTITY_MAILBOX_PULL_V2_PATH,
            IDENTITY_MAILBOX_PULL_V3_CONTENT_TYPE,
            None,
            recovered.active.session_id,
            recovered.active.session_secret,
            pull_request,
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND,
    );
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one HTTPS boundary test keeps opaque CAS, exact replay, multi-device read, conflict, privacy, and revoke behavior coherent"
)]
async fn account_read_cursor_is_opaque_exact_cas_and_rechecks_device_revocation()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(NOW)),
    ));
    let owner = enroll_active_device(&identity_store, 141, 142, 143, [144; 32]).await?;
    let second = add_active_device(&identity_store, &owner, 145, [146; 32]).await?;
    let mailbox_id = MailboxId::new();
    assert_eq!(
        send_registration(
            app.clone(),
            "account-cursor-register",
            owner.session_id,
            owner.session_secret,
            mailbox_id,
            mailbox_registration_body(
                mailbox_id,
                owner.identity_id,
                owner.device_id,
                [147; 32],
                UtcMillis::new(EXPIRY)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let head = Sha256Digest::from_bytes(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT head_hash FROM identity.log_heads WHERE identity_id=$1",
        )
        .bind(owner.identity_id.to_string())
        .fetch_one(harness.admin_pool())
        .await?
        .try_into()
        .map_err(|_| "identity head digest size")?,
    );
    let conversation = Sha256Digest::hash_domain(
        b"test-account-cursor-conversation\0",
        b"never-store-this-conversation-id",
    );
    let first_body = account_read_cursor_write_body(conversation, 0, 1, &[0x91; 48], head)?;
    let first = send_v2(
        app.clone(),
        ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
        ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
        Some("account-cursor-write-0001"),
        owner.session_id,
        owner.session_secret,
        first_body.clone(),
    )
    .await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_receipt = response_bytes(first).await?;
    let replay = send_v2(
        app.clone(),
        ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
        ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
        Some("account-cursor-write-0001"),
        owner.session_id,
        owner.session_secret,
        first_body,
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(replay).await?, first_receipt);
    assert_eq!(
        send_v2(
            app.clone(),
            ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
            ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
            Some("account-cursor-write-0001"),
            owner.session_id,
            owner.session_secret,
            account_read_cursor_write_body(conversation, 0, 1, &[0x90; 48], head)?,
        )
        .await?
        .status(),
        StatusCode::CONFLICT,
    );

    let query = send_v2(
        app.clone(),
        ACCOUNT_READ_CURSOR_QUERY_V1_PATH,
        ACCOUNT_READ_CURSOR_QUERY_V1_CONTENT_TYPE,
        None,
        second.session_id,
        second.session_secret,
        account_read_cursor_query_body(conversation)?,
    )
    .await?;
    assert_eq!(query.status(), StatusCode::OK);
    let query_bytes = response_bytes(query).await?;
    let CanonicalValue::Map(query_fields) = decode_deterministic_cbor(&query_bytes)? else {
        return Err("account cursor query receipt not a map".into());
    };
    assert_eq!(query_fields[2].1, CanonicalValue::Unsigned(1));
    assert_eq!(query_fields[3].1, CanonicalValue::Bytes(vec![0x91; 48]));
    assert!(
        !query_bytes
            .windows(b"never-store-this-conversation-id".len())
            .any(|window| window == b"never-store-this-conversation-id")
    );

    let stale = send_v2(
        app.clone(),
        ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
        ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
        Some("account-cursor-stale-0001"),
        second.session_id,
        second.session_secret,
        account_read_cursor_write_body(conversation, 0, 1, &[0x92; 48], head)?,
    )
    .await?;
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    let stale_head = send_v2(
        app.clone(),
        ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
        ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
        Some("account-cursor-head-0001"),
        second.session_id,
        second.session_secret,
        account_read_cursor_write_body(
            conversation,
            1,
            2,
            &[0x93; 48],
            Sha256Digest::from_bytes([0x94; 32]),
        )?,
    )
    .await?;
    assert_eq!(stale_head.status(), StatusCode::CONFLICT);
    let second_body = account_read_cursor_write_body(conversation, 1, 2, &[0x93; 48], head)?;
    assert_eq!(
        send_v2(
            app.clone(),
            ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
            ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
            Some("account-cursor-write-0002"),
            second.session_id,
            second.session_secret,
            second_body.clone(),
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    revoke_active_device(&identity_store, &second).await?;
    let revoked_invalidation: (String, Vec<u8>, i64) = sqlx::query_as(
        "SELECT journal.event_kind,journal.subject_digest,
                (SELECT count(*) FROM realtime.outbox AS pending
                  WHERE pending.identity_id=journal.identity_id AND pending.cursor=journal.cursor)
           FROM realtime.journal AS journal
          WHERE journal.identity_id=$1 ORDER BY journal.cursor DESC LIMIT 1",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(revoked_invalidation.0, "device_revoked");
    assert_eq!(revoked_invalidation.1.len(), 32);
    assert_eq!(revoked_invalidation.2, 1);
    assert_eq!(
        send_v2(
            app,
            ACCOUNT_READ_CURSOR_WRITE_V1_PATH,
            ACCOUNT_READ_CURSOR_WRITE_V1_CONTENT_TYPE,
            Some("account-cursor-write-0002"),
            second.session_id,
            second.session_secret,
            second_body,
        )
        .await?
        .status(),
        StatusCode::UNAUTHORIZED,
    );
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one boundary test keeps fenced acquire, replay, ACK, heartbeat, expiry, and durable gap recovery coherent"
)]
async fn realtime_sync_fences_old_leases_and_requires_catch_up_after_a_gap()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let realtime_store =
        RealtimeSyncStore::connect(harness.realtime_sync_runtime_options(), 4).await?;
    let realtime_now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(realtime_now)),
    ));
    let owner =
        enroll_active_device_at(&identity_store, 121, 122, 123, [124; 32], realtime_now).await?;
    let credential = DeviceSessionCredential::new(owner.session_id, owner.session_secret)?;

    let mailbox_id = MailboxId::new();
    let capability = [125; 32];
    let registration_body = mailbox_registration_body(
        mailbox_id,
        owner.identity_id,
        owner.device_id,
        capability,
        UtcMillis::new(realtime_now + 600_000)?,
    )?;
    let registration = MailboxRegistrationCommand::new(
        Sha256Digest::hash_domain(b"test-realtime-register\0", b"register"),
        mailbox_id,
        owner.identity_id,
        owner.device_id,
        Sha256Digest::hash_domain(MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN, &capability),
        UtcMillis::new(realtime_now + 600_000)?,
        registration_body,
    )?;
    MailboxRepository
        .register(
            &mailbox_store,
            &credential,
            &registration,
            UtcMillis::new(realtime_now)?,
        )
        .await?;
    let envelope_id = EnvelopeId::new();
    assert_eq!(
        send_envelope(
            app,
            "realtime-envelope-0001",
            capability,
            mailbox_id,
            envelope_id,
            mailbox_envelope_body(
                envelope_id,
                b"opaque",
                UtcMillis::new(realtime_now + 600_000)?,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    sqlx::query(
        "UPDATE realtime.journal SET created_at_ms=$2,expires_at_ms=$3 \
         WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .bind(realtime_now - 1)
    .bind(realtime_now + 60_000)
    .execute(harness.admin_pool())
    .await?;

    let worker_id = Uuid::now_v7();
    assert!(matches!(
        realtime_store
            .compact_expired(UtcMillis::new(realtime_now + 120_000)?)
            .await,
        Err(RealtimeSyncError::Database(_))
    ));
    let abandoned = realtime_store
        .claim_outbox(worker_id, UtcMillis::new(realtime_now)?)
        .await?;
    assert_eq!(abandoned.notifications.len(), 3);
    assert_eq!(
        abandoned
            .notifications
            .iter()
            .map(|notification| notification.event.kind)
            .collect::<Vec<_>>(),
        vec![
            InvalidationKind::IdentityHeadChanged,
            InvalidationKind::IdentityHeadChanged,
            InvalidationKind::MailboxDelivery,
        ]
    );
    assert!(
        realtime_store
            .claim_outbox(worker_id, UtcMillis::new(realtime_now + 1)?)
            .await?
            .notifications
            .is_empty()
    );
    let reclaimed = realtime_store
        .claim_outbox(
            worker_id,
            UtcMillis::new(realtime_now + OUTBOX_CLAIM_TTL_MILLIS)?,
        )
        .await?;
    assert_eq!(reclaimed.notifications, abandoned.notifications);
    assert_ne!(reclaimed.claim_id, abandoned.claim_id);
    realtime_store
        .mark_outbox_published(
            &abandoned,
            UtcMillis::new(realtime_now + OUTBOX_CLAIM_TTL_MILLIS + 1)?,
        )
        .await?;
    realtime_store
        .mark_outbox_published(
            &reclaimed,
            UtcMillis::new(realtime_now + OUTBOX_CLAIM_TTL_MILLIS + 1)?,
        )
        .await?;
    realtime_store
        .mark_outbox_published(
            &reclaimed,
            UtcMillis::new(realtime_now + OUTBOX_CLAIM_TTL_MILLIS + 2)?,
        )
        .await?;
    let publication: (i32, bool) = sqlx::query_as(
        "SELECT attempts,published_at_ms IS NOT NULL FROM realtime.outbox
          WHERE identity_id=$1 AND cursor=1",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(publication, (2, true));

    let first = realtime_store
        .acquire(
            &credential,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now)?,
        )
        .await?;
    let current = realtime_store
        .acquire(
            &credential,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now + 1)?,
        )
        .await?;
    assert_eq!(current.fence.get(), first.fence.get() + 1);
    assert!(matches!(
        realtime_store
            .replay(
                &credential,
                first,
                SafeUint::new(0)?,
                UtcMillis::new(realtime_now + 2)?
            )
            .await,
        Err(RealtimeSyncError::StaleLease)
    ));

    let ReplayPage::Events { highwater, events } = realtime_store
        .replay(
            &credential,
            current,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now + 2)?,
        )
        .await?
    else {
        panic!("durable event must replay before expiry");
    };
    assert_eq!(highwater.get(), 3);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].cursor.get(), 1);
    realtime_store
        .acknowledge(
            &credential,
            current,
            SafeUint::new(3)?,
            UtcMillis::new(realtime_now + 3)?,
        )
        .await?;

    let renewed = realtime_store
        .heartbeat(
            &credential,
            current,
            UtcMillis::new(realtime_now + HEARTBEAT_INTERVAL_MILLIS)?,
        )
        .await?;
    assert_eq!(
        renewed.expires_at.get(),
        realtime_now + HEARTBEAT_INTERVAL_MILLIS + LEASE_TTL_MILLIS
    );
    assert!(matches!(
        realtime_store
            .replay(
                &credential,
                renewed,
                SafeUint::new(3)?,
                UtcMillis::new(renewed.expires_at.get())?,
            )
            .await,
        Err(RealtimeSyncError::StaleLease)
    ));

    let mut uncommitted = harness.admin_pool().begin().await?;
    sqlx::query("UPDATE realtime.identity_heads SET next_cursor=4 WHERE identity_id=$1")
        .bind(owner.identity_id.to_string())
        .execute(&mut *uncommitted)
        .await?;
    sqlx::query(
        "INSERT INTO realtime.journal(
             identity_id,cursor,event_kind,subject_digest,created_at_ms,expires_at_ms
         ) VALUES($1,4,'durable_invalidation',$2,$3,$4)",
    )
    .bind(owner.identity_id.to_string())
    .bind(vec![0x51_u8; 32])
    .bind(realtime_now + 20)
    .bind(realtime_now + 60_000)
    .execute(&mut *uncommitted)
    .await?;
    sqlx::query("INSERT INTO realtime.outbox(identity_id,cursor) VALUES($1,4)")
        .bind(owner.identity_id.to_string())
        .execute(&mut *uncommitted)
        .await?;
    assert!(
        realtime_store
            .claim_outbox(worker_id, UtcMillis::new(realtime_now + 20)?)
            .await?
            .notifications
            .is_empty()
    );
    uncommitted.commit().await?;
    let committed = realtime_store
        .claim_outbox(worker_id, UtcMillis::new(realtime_now + 20)?)
        .await?;
    assert_eq!(committed.notifications.len(), 1);
    assert_eq!(committed.notifications[0].event.cursor.get(), 4);
    realtime_store
        .mark_outbox_published(&committed, UtcMillis::new(realtime_now + 21)?)
        .await?;

    sqlx::query(
        "UPDATE realtime.journal
            SET created_at_ms=$2,
                expires_at_ms=CASE WHEN cursor=2 THEN $3 ELSE $4 END
          WHERE identity_id=$1 AND cursor BETWEEN 1 AND 4",
    )
    .bind(owner.identity_id.to_string())
    .bind(realtime_now - 2)
    .bind(realtime_now - 1)
    .bind(realtime_now + 60_000)
    .execute(harness.admin_pool())
    .await?;
    let gap_lease = realtime_store
        .acquire(
            &credential,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now + 4)?,
        )
        .await?;
    assert!(matches!(
        realtime_store
            .replay(
                &credential,
                gap_lease,
                SafeUint::new(0)?,
                UtcMillis::new(realtime_now + 4)?,
            )
            .await?,
        ReplayPage::CatchUpRequired { highwater } if highwater.get() == 4
    ));
    realtime_store
        .compact_expired(UtcMillis::new(realtime_now + 4)?)
        .await?;
    let retained_realtime: (i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT count(*) FROM realtime.journal WHERE identity_id=$1),
            (SELECT count(*) FROM realtime.outbox WHERE identity_id=$1),
            (SELECT journal_floor FROM realtime.identity_heads WHERE identity_id=$1)",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(retained_realtime, (4, 4, 1));
    sqlx::query(
        "UPDATE realtime.journal SET expires_at_ms=$2
          WHERE identity_id=$1 AND cursor=1",
    )
    .bind(owner.identity_id.to_string())
    .bind(realtime_now - 1)
    .execute(harness.admin_pool())
    .await?;
    realtime_store
        .compact_expired(UtcMillis::new(realtime_now + 5)?)
        .await?;
    let compacted_prefix: (i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT count(*) FROM realtime.journal WHERE identity_id=$1),
            (SELECT count(*) FROM realtime.outbox WHERE identity_id=$1),
            (SELECT journal_floor FROM realtime.identity_heads WHERE identity_id=$1)",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(compacted_prefix, (2, 2, 3));
    let catch_up_lease = realtime_store
        .acquire(
            &credential,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now + 5)?,
        )
        .await?;
    assert!(matches!(
        realtime_store
            .replay(
                &credential,
                catch_up_lease,
                SafeUint::new(0)?,
                UtcMillis::new(realtime_now + 5)?,
            )
            .await?,
        ReplayPage::CatchUpRequired { highwater } if highwater.get() == 4
    ));
    let ReplayPage::Events { events, .. } = realtime_store
        .replay(
            &credential,
            catch_up_lease,
            SafeUint::new(2)?,
            UtcMillis::new(realtime_now + 5)?,
        )
        .await?
    else {
        panic!("cursor at compacted floor must resume contiguously");
    };
    assert_eq!(
        events
            .iter()
            .map(|event| event.cursor.get())
            .collect::<Vec<_>>(),
        vec![3, 4]
    );
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one lease-edge boundary proves held revoke and replacement fences before testing both terminal outcomes"
)]
async fn realtime_ephemeral_edges_reject_replaced_socket_and_revoked_session()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let realtime_store =
        RealtimeSyncStore::connect(harness.realtime_sync_runtime_options(), 4).await?;
    let realtime_now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let owner =
        enroll_active_device_at(&identity_store, 221, 222, 223, [224; 32], realtime_now).await?;
    let credential = DeviceSessionCredential::new(owner.session_id, owner.session_secret)?;

    // The gateway guard owns the identity mutation fence and a shared lock on
    // the exact lease row through its external edge. Neither a revoke nor a
    // replacement Hello can cross that edge and commit midway through it.
    let guarded_socket = realtime_store
        .acquire(
            &credential,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now)?,
        )
        .await?;
    let operation = realtime_store
        .begin_lease_operation(
            &credential,
            guarded_socket,
            UtcMillis::new(realtime_now + 1)?,
        )
        .await?;
    let identity_lock_key = i64::from_be_bytes(owner.identity_id.digest_bytes()[..8].try_into()?);
    let mut revoke_lock_probe = harness.admin_pool().begin().await?;
    let revoke_lock_available: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(identity_lock_key)
        .fetch_one(&mut *revoke_lock_probe)
        .await?;
    assert!(!revoke_lock_available);
    revoke_lock_probe.rollback().await?;

    let mut replacement_probe = harness.admin_pool().begin().await?;
    let replacement_error = sqlx::query_scalar::<_, i64>(
        "SELECT fence FROM realtime.device_leases
          WHERE identity_id=$1 AND device_id=$2 FOR UPDATE NOWAIT",
    )
    .bind(owner.identity_id.to_string())
    .bind(*owner.device_id.as_uuid())
    .fetch_one(&mut *replacement_probe)
    .await
    .expect_err("the operation guard must fence lease replacement");
    assert_eq!(
        replacement_error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some(std::borrow::Cow::Borrowed("55P03")),
    );
    replacement_probe.rollback().await?;

    operation.finish().await?;
    let mut released_probe = harness.admin_pool().begin().await?;
    let revoke_lock_available: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(identity_lock_key)
        .fetch_one(&mut *released_probe)
        .await?;
    assert!(revoke_lock_available);
    let released_fence: i64 = sqlx::query_scalar(
        "SELECT fence FROM realtime.device_leases
          WHERE identity_id=$1 AND device_id=$2 FOR UPDATE NOWAIT",
    )
    .bind(owner.identity_id.to_string())
    .bind(*owner.device_id.as_uuid())
    .fetch_one(&mut *released_probe)
    .await?;
    assert_eq!(released_fence, i64::try_from(guarded_socket.fence.get())?);
    released_probe.rollback().await?;

    // These leases now model two simultaneously open sockets for one device.
    // The second Hello replaces the first fence before the old socket's next
    // guarded scope, send, or peer-delivery edge.
    let latest_socket = realtime_store
        .acquire(
            &credential,
            SafeUint::new(0)?,
            UtcMillis::new(realtime_now + 2)?,
        )
        .await?;
    assert!(matches!(
        realtime_store
            .begin_lease_operation(
                &credential,
                guarded_socket,
                UtcMillis::new(realtime_now + 3)?,
            )
            .await,
        Err(RealtimeSyncError::StaleLease)
    ));
    realtime_store
        .begin_lease_operation(
            &credential,
            latest_socket,
            UtcMillis::new(realtime_now + 3)?,
        )
        .await?
        .finish()
        .await?;

    let repository = IdentityLogRepository::new();
    let head = repository
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing before realtime revoke")?
        .head();
    let revoke = signed_event(
        &owner.root,
        owner.identity_id,
        head.sequence().get() + 1,
        Some(head.hash()),
        realtime_now + 4,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: owner.device_id,
        },
    )?;
    let revocation_operation = realtime_store
        .begin_lease_operation(
            &credential,
            latest_socket,
            UtcMillis::new(realtime_now + 4)?,
        )
        .await?;
    let mut revocation_probe = harness.admin_pool().begin().await?;
    let revocation_can_cross_edge: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
            .bind(identity_lock_key)
            .fetch_one(&mut *revocation_probe)
            .await?;
    assert!(!revocation_can_cross_edge);
    revocation_probe.rollback().await?;
    revocation_operation.finish().await?;
    assert!(matches!(
        repository
            .append(
                &identity_store,
                &IdentityAppendCommand::new(
                    Sha256Digest::hash_domain(b"test-realtime-edge-revoke\0", &[225]),
                    Some(head),
                    revoke.to_deterministic_cbor()?,
                )?,
                UtcMillis::new(realtime_now + 4)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    assert!(matches!(
        realtime_store
            .begin_lease_operation(
                &credential,
                latest_socket,
                UtcMillis::new(realtime_now + 5)?,
            )
            .await,
        Err(RealtimeSyncError::Unauthorized)
    ));
    Ok(())
}

#[tokio::test]
#[ignore = "requires the disposable three-node Docker Compose cluster"]
#[allow(
    clippy::too_many_lines,
    reason = "one real three-node boundary keeps post-admission delivery, response-loss replay, offline pull, acknowledgement, and node isolation coherent"
)]
async fn three_node_compose_delivers_post_admission_private_envelope_exactly()
-> Result<(), Box<dyn Error>> {
    if std::env::var("DTX_THREE_NODE_COMPOSE_ACCEPTANCE").as_deref() != Ok("1") {
        return Err(
            "set DTX_THREE_NODE_COMPOSE_ACCEPTANCE=1 for the disposable local cluster".into(),
        );
    }

    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let expires_at = UtcMillis::new(now.checked_add(600_000).ok_or("test expiry overflow")?)?;
    let identity_a = IdentityPgStore::connect(
        PgConnectOptions::from_str(
            "postgres://dtx_identity_node@127.0.0.1:15432/dtx_node_a?sslmode=disable",
        )?,
        2,
    )
    .await?;
    let identity_b = IdentityPgStore::connect(
        PgConnectOptions::from_str(
            "postgres://dtx_identity_node@127.0.0.1:15432/dtx_node_b?sslmode=disable",
        )?,
        2,
    )
    .await?;
    let identity_c = IdentityPgStore::connect(
        PgConnectOptions::from_str(
            "postgres://dtx_identity_node@127.0.0.1:15432/dtx_node_c?sslmode=disable",
        )?,
        2,
    )
    .await?;
    let sender = enroll_active_device_at(&identity_a, 171, 172, 173, [174; 32], now).await?;
    let recipient = enroll_active_device_at(&identity_b, 181, 182, 183, [184; 32], now).await?;
    let outsider = enroll_active_device_at(&identity_c, 191, 192, 193, [194; 32], now).await?;
    assert_ne!(sender.identity_id, recipient.identity_id);
    assert_ne!(outsider.identity_id, recipient.identity_id);

    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    for port in [18_080, 18_081, 18_082] {
        let health = client
            .get(format!("http://127.0.0.1:{port}/local-health"))
            .send()
            .await?;
        assert_eq!(health.status(), StatusCode::NO_CONTENT);
    }

    let node_a = "http://127.0.0.1:18080";
    let node_b = "http://127.0.0.1:18081";
    let node_c = "http://127.0.0.1:18082";
    let mailbox_id = MailboxId::new();
    let envelope_id = EnvelopeId::new();
    let capability = [195; 32];
    let register_path =
        MAILBOX_REGISTER_PATH_TEMPLATE.replace("{mailbox_id}", &mailbox_id.to_string());
    let register = send_network_mailbox_request(
        &client,
        reqwest::Method::PUT,
        node_b,
        &register_path,
        MAILBOX_REGISTER_CONTENT_TYPE,
        Some("compose-mailbox-register-0001"),
        device_session_authorization(recipient.session_id, recipient.session_secret),
        mailbox_registration_body(
            mailbox_id,
            recipient.identity_id,
            recipient.device_id,
            capability,
            expires_at,
        )?,
    )
    .await?;
    assert_eq!(register.status(), StatusCode::CREATED);
    assert_network_content_type(&register, MAILBOX_REGISTER_RECEIPT_CONTENT_TYPE);

    // V30/Welcome establishes the peer relationship; the relay intentionally
    // authorizes the sender only with the resulting write-only capability and
    // never learns or authenticates the MLS sender identity.
    let ciphertext = b"opaque-mls-application-ciphertext-v1";
    let envelope_body = mailbox_envelope_body(envelope_id, ciphertext, expires_at)?;
    let envelope_path = MAILBOX_ENQUEUE_PATH_TEMPLATE
        .replace("{mailbox_id}", &mailbox_id.to_string())
        .replace("{envelope_id}", &envelope_id.to_string());
    {
        let lost_response = send_network_mailbox_request(
            &client,
            reqwest::Method::PUT,
            node_b,
            &envelope_path,
            MAILBOX_ENVELOPE_CONTENT_TYPE,
            Some("compose-mailbox-enqueue-0001"),
            mailbox_capability_authorization(capability),
            envelope_body.clone(),
        )
        .await?;
        assert_eq!(lost_response.status(), StatusCode::CREATED);
        assert_network_content_type(&lost_response, MAILBOX_ENVELOPE_RECEIPT_CONTENT_TYPE);
        // Deliberately do not consume the response body, matching a client-side
        // disconnect after the server transaction committed.
    }
    let replay = send_network_mailbox_request(
        &client,
        reqwest::Method::PUT,
        node_b,
        &envelope_path,
        MAILBOX_ENVELOPE_CONTENT_TYPE,
        Some("compose-mailbox-enqueue-0001"),
        mailbox_capability_authorization(capability),
        envelope_body.clone(),
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_network_content_type(&replay, MAILBOX_ENVELOPE_RECEIPT_CONTENT_TYPE);
    let replay_receipt = replay.bytes().await?.to_vec();
    let admin_b =
        sqlx::PgPool::connect("postgres://postgres@127.0.0.1:15432/dtx_node_b?sslmode=disable")
            .await?;
    let durable_receipt: Vec<u8> = sqlx::query_scalar(
        "SELECT receipt_bytes
           FROM messaging.mailbox_enqueue_claims
          WHERE mailbox_id=$1 AND envelope_id=$2",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(*envelope_id.as_uuid())
    .fetch_one(&admin_b)
    .await?;
    assert_eq!(replay_receipt, durable_receipt);
    let stored_envelopes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM messaging.mailbox_envelopes
          WHERE mailbox_id=$1 AND envelope_id=$2",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(*envelope_id.as_uuid())
    .fetch_one(&admin_b)
    .await?;
    assert_eq!(stored_envelopes, 1);

    let conflicting_body =
        mailbox_envelope_body(envelope_id, b"different-opaque-ciphertext", expires_at)?;
    let conflict = send_network_mailbox_request(
        &client,
        reqwest::Method::PUT,
        node_b,
        &envelope_path,
        MAILBOX_ENVELOPE_CONTENT_TYPE,
        Some("compose-mailbox-enqueue-0001"),
        mailbox_capability_authorization(capability),
        conflicting_body,
    )
    .await?;
    assert_network_mailbox_error(conflict, StatusCode::CONFLICT, "IDEMPOTENCY_CONFLICT").await?;

    let pull_path = MAILBOX_PULL_PATH_TEMPLATE.replace("{mailbox_id}", &mailbox_id.to_string());
    for (origin, actor, expected_status, expected_code) in [
        (
            node_a,
            &sender,
            StatusCode::NOT_FOUND,
            "MAILBOX_UNAVAILABLE",
        ),
        (
            node_c,
            &outsider,
            StatusCode::NOT_FOUND,
            "MAILBOX_UNAVAILABLE",
        ),
        (
            node_b,
            &outsider,
            StatusCode::UNAUTHORIZED,
            "DEVICE_AUTHENTICATION_FAILED",
        ),
    ] {
        let isolated = send_network_mailbox_request(
            &client,
            reqwest::Method::POST,
            origin,
            &pull_path,
            MAILBOX_PULL_CONTENT_TYPE,
            None,
            device_session_authorization(actor.session_id, actor.session_secret),
            mailbox_pull_body(SafeUint::new(0)?, 100)?,
        )
        .await?;
        assert_network_mailbox_error(isolated, expected_status, expected_code).await?;
    }

    // The recipient was offline for the complete enqueue/replay sequence and
    // now resumes from its durable cursor. Pull remains non-consuming until ACK.
    let first_pull = send_network_mailbox_request(
        &client,
        reqwest::Method::POST,
        node_b,
        &pull_path,
        MAILBOX_PULL_CONTENT_TYPE,
        None,
        device_session_authorization(recipient.session_id, recipient.session_secret),
        mailbox_pull_body(SafeUint::new(0)?, 100)?,
    )
    .await?;
    assert_eq!(first_pull.status(), StatusCode::OK);
    assert_network_content_type(&first_pull, MAILBOX_PULL_RECEIPT_CONTENT_TYPE);
    let first_pull_receipt = first_pull.bytes().await?.to_vec();
    assert_pull_receipt(&first_pull_receipt, mailbox_id, envelope_id, ciphertext)?;
    let repeated_pull = send_network_mailbox_request(
        &client,
        reqwest::Method::POST,
        node_b,
        &pull_path,
        MAILBOX_PULL_CONTENT_TYPE,
        None,
        device_session_authorization(recipient.session_id, recipient.session_secret),
        mailbox_pull_body(SafeUint::new(0)?, 100)?,
    )
    .await?;
    assert_eq!(repeated_pull.status(), StatusCode::OK);
    assert_eq!(repeated_pull.bytes().await?.to_vec(), first_pull_receipt);

    let ack_path = MAILBOX_ACK_PATH_TEMPLATE.replace("{mailbox_id}", &mailbox_id.to_string());
    let ack_body = mailbox_ack_body(&[envelope_id])?;
    {
        let lost_ack = send_network_mailbox_request(
            &client,
            reqwest::Method::POST,
            node_b,
            &ack_path,
            MAILBOX_ACK_CONTENT_TYPE,
            Some("compose-mailbox-acknowledge-0001"),
            device_session_authorization(recipient.session_id, recipient.session_secret),
            ack_body.clone(),
        )
        .await?;
        assert_eq!(lost_ack.status(), StatusCode::CREATED);
        assert_network_content_type(&lost_ack, MAILBOX_ACK_RECEIPT_CONTENT_TYPE);
    }
    let ack_replay = send_network_mailbox_request(
        &client,
        reqwest::Method::POST,
        node_b,
        &ack_path,
        MAILBOX_ACK_CONTENT_TYPE,
        Some("compose-mailbox-acknowledge-0001"),
        device_session_authorization(recipient.session_id, recipient.session_secret),
        ack_body,
    )
    .await?;
    assert_eq!(ack_replay.status(), StatusCode::OK);
    assert_network_content_type(&ack_replay, MAILBOX_ACK_RECEIPT_CONTENT_TYPE);
    let ack_replay_receipt = ack_replay.bytes().await?.to_vec();
    let durable_ack_receipt: Vec<u8> = sqlx::query_scalar(
        "SELECT receipt_bytes
           FROM messaging.mailbox_ack_claims
          WHERE mailbox_id=$1 AND owner_identity_id=$2 AND owner_device_id=$3",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(recipient.identity_id.to_string())
    .bind(*recipient.device_id.as_uuid())
    .fetch_one(&admin_b)
    .await?;
    assert_eq!(ack_replay_receipt, durable_ack_receipt);

    let after_ack = send_network_mailbox_request(
        &client,
        reqwest::Method::POST,
        node_b,
        &pull_path,
        MAILBOX_PULL_CONTENT_TYPE,
        None,
        device_session_authorization(recipient.session_id, recipient.session_secret),
        mailbox_pull_body(SafeUint::new(0)?, 100)?,
    )
    .await?;
    assert_eq!(after_ack.status(), StatusCode::OK);
    let after_ack = after_ack.bytes().await?.to_vec();
    assert_empty_pull_receipt(&after_ack, mailbox_id)?;
    let resumed_cursor = send_network_mailbox_request(
        &client,
        reqwest::Method::POST,
        node_b,
        &pull_path,
        MAILBOX_PULL_CONTENT_TYPE,
        None,
        device_session_authorization(recipient.session_id, recipient.session_secret),
        mailbox_pull_body(SafeUint::new(1)?, 100)?,
    )
    .await?;
    assert_eq!(resumed_cursor.status(), StatusCode::OK);
    assert_eq!(resumed_cursor.bytes().await?.to_vec(), after_ack);
    let terminal_state: (String, i32, i64) = sqlx::query_as(
        "SELECT envelope.state, mailbox.active_envelope_count, mailbox.active_envelope_bytes
           FROM messaging.mailbox_envelopes envelope
           JOIN messaging.mailboxes mailbox USING (mailbox_id)
          WHERE envelope.mailbox_id=$1 AND envelope.envelope_id=$2",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(*envelope_id.as_uuid())
    .fetch_one(&admin_b)
    .await?;
    assert_eq!(terminal_state, ("acked".to_owned(), 0, 0));
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end attachment lifecycle keeps replay assertions together"
)]
async fn opaque_attachment_is_exact_idempotent_and_cancel_revokes_read()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let owner = enroll_active_device(&identity_store, 91, 92, 93, [94; 32]).await?;
    let credential = DeviceSessionCredential::new(owner.session_id, owner.session_secret)?;
    let object_id = Uuid::now_v7();
    let ciphertext = (0_u8..64).collect::<Vec<_>>();
    let chunk_digest = Sha256Digest::from_bytes(Sha256::digest(&ciphertext).into());
    let mut manifest_bytes = b"DTXA1".to_vec();
    manifest_bytes.extend_from_slice(&1_u16.to_be_bytes());
    manifest_bytes.extend_from_slice(&0_u16.to_be_bytes());
    manifest_bytes.extend_from_slice(&u32::try_from(ciphertext.len())?.to_be_bytes());
    manifest_bytes.extend_from_slice(chunk_digest.as_bytes());
    manifest_bytes.extend_from_slice(&17_u32.to_be_bytes());
    manifest_bytes.extend_from_slice(&[7; 17]);
    let manifest = AttachmentManifest::parse(manifest_bytes.clone()).unwrap();
    let request = AttachmentCreate {
        object_id,
        owner_identity_id: owner.identity_id,
        owner_device_id: owner.device_id,
        manifest_digest: Sha256Digest::from_bytes(Sha256::digest(&manifest_bytes).into()),
        chunk_count: 1,
        ciphertext_bytes: ciphertext.len() as u64,
        expires_at: UtcMillis::new(EXPIRY)?,
    };
    let upload = AttachmentCapability::new([95; 32]);
    let read = AttachmentCapability::new([96; 32]);
    assert_eq!(
        AttachmentRepository
            .create(
                &mailbox_store,
                &credential,
                &request,
                &upload,
                &read,
                UtcMillis::new(NOW)?
            )
            .await
            .unwrap(),
        AttachmentStatus::Created
    );
    assert_eq!(
        AttachmentRepository
            .create(
                &mailbox_store,
                &credential,
                &request,
                &upload,
                &read,
                UtcMillis::new(NOW + 1)?
            )
            .await
            .unwrap(),
        AttachmentStatus::Replay
    );
    let idempotency = Sha256Digest::hash_domain(b"attachment-test-idempotency\0", b"chunk-0");
    assert_eq!(
        AttachmentRepository
            .put_chunk(
                &mailbox_store,
                object_id,
                0,
                &upload,
                idempotency,
                chunk_digest,
                &ciphertext,
                UtcMillis::new(NOW + 1)?
            )
            .await
            .unwrap(),
        AttachmentStatus::Created
    );
    assert_eq!(
        AttachmentRepository
            .put_chunk(
                &mailbox_store,
                object_id,
                0,
                &upload,
                idempotency,
                chunk_digest,
                &ciphertext,
                UtcMillis::new(NOW + 2)?
            )
            .await
            .unwrap(),
        AttachmentStatus::Replay
    );
    let mut changed = ciphertext.clone();
    changed[0] ^= 1;
    assert!(matches!(
        AttachmentRepository
            .put_chunk(
                &mailbox_store,
                object_id,
                0,
                &upload,
                idempotency,
                Sha256Digest::from_bytes(Sha256::digest(&changed).into()),
                &changed,
                UtcMillis::new(NOW + 3)?
            )
            .await,
        Err(AttachmentError::Conflict)
    ));
    let second_object_id = Uuid::now_v7();
    let second_request = AttachmentCreate {
        object_id: second_object_id,
        owner_identity_id: owner.identity_id,
        owner_device_id: owner.device_id,
        manifest_digest: request.manifest_digest,
        chunk_count: 2,
        ciphertext_bytes: (ciphertext.len() * 2) as u64,
        expires_at: UtcMillis::new(EXPIRY)?,
    };
    assert_eq!(
        AttachmentRepository
            .create(
                &mailbox_store,
                &credential,
                &second_request,
                &upload,
                &read,
                UtcMillis::new(NOW + 3)?,
            )
            .await
            .unwrap(),
        AttachmentStatus::Created
    );
    AttachmentRepository
        .put_chunk(
            &mailbox_store,
            second_object_id,
            0,
            &upload,
            idempotency,
            chunk_digest,
            &ciphertext,
            UtcMillis::new(NOW + 3)?,
        )
        .await
        .unwrap();
    assert!(matches!(
        AttachmentRepository
            .put_chunk(
                &mailbox_store,
                second_object_id,
                1,
                &upload,
                idempotency,
                chunk_digest,
                &ciphertext,
                UtcMillis::new(NOW + 3)?,
            )
            .await,
        Err(AttachmentError::Conflict)
    ));
    assert_eq!(
        AttachmentRepository
            .finalize(
                &mailbox_store,
                object_id,
                &upload,
                &manifest,
                UtcMillis::new(NOW + 4)?
            )
            .await
            .unwrap(),
        AttachmentStatus::Ready
    );
    assert_eq!(
        AttachmentRepository
            .read_chunk(
                &mailbox_store,
                object_id,
                0,
                &read,
                UtcMillis::new(NOW + 5)?
            )
            .await
            .unwrap()
            .ciphertext,
        ciphertext
    );
    let cancel_credential = DeviceSessionCredential::new(owner.session_id, owner.session_secret)?;
    assert_eq!(
        AttachmentRepository
            .cancel(
                &mailbox_store,
                &cancel_credential,
                object_id,
                UtcMillis::new(NOW + 6)?,
            )
            .await
            .unwrap(),
        AttachmentStatus::Cancelled
    );
    assert_eq!(
        AttachmentRepository
            .cancel(
                &mailbox_store,
                &cancel_credential,
                object_id,
                UtcMillis::new(NOW + 7)?,
            )
            .await
            .unwrap(),
        AttachmentStatus::Replay
    );
    assert!(matches!(
        AttachmentRepository
            .read_manifest(&mailbox_store, object_id, &read, UtcMillis::new(NOW + 8)?)
            .await,
        Err(AttachmentError::Unavailable)
    ));
    Ok(())
}

struct RecoveredDevice {
    active: ActiveDevice,
    request_id: DeviceEnrollmentChallengeId,
    request_digest: Sha256Digest,
    approved_head: IdentityLogHead,
    recipient_package_digest: Sha256Digest,
}

struct ActiveDevice {
    root: SigningKey,
    recovery: SigningKey,
    identity_id: IdentityId,
    device_id: DeviceId,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn enroll_history_recovery_device(
    store: &IdentityPgStore,
    owner: &ActiveDevice,
    observed_head: IdentityLogHead,
    candidate_seed: u8,
    encryption_seed: u8,
    session_secret: [u8; 32],
    capability_bytes: [u8; 32],
    request_expires_at: i64,
) -> Result<RecoveredDevice, Box<dyn Error>> {
    let candidate = SigningKey::from_bytes(&[candidate_seed; 32]);
    let candidate_public = public_key(&candidate)?;
    let recipient_key = DeviceEncryptionPublicKey::try_from([encryption_seed; 32])?;
    let candidate_device_id = DeviceId::new();
    let request_id = DeviceEnrollmentChallengeId::new();
    let issued_at = UtcMillis::new(NOW + 1)?;
    let expires_at = UtcMillis::new(request_expires_at)?;
    let unsigned = history_recovery_request_unsigned_canonical_bytes(
        request_id,
        owner.identity_id,
        candidate_device_id,
        candidate_public,
        recipient_key,
        observed_head,
        issued_at,
        expires_at,
    )?;
    let candidate_signature = signature(
        &candidate,
        &history_recovery_request_signature_input(&unsigned),
    );
    let CanonicalValue::Map(mut request_fields) = decode_deterministic_cbor(&unsigned)? else {
        return Err("history recovery unsigned request is not a map".into());
    };
    request_fields.push((
        CanonicalValue::Unsigned(12),
        candidate_signature.to_canonical_value(),
    ));
    let exact_request = encode_deterministic_cbor(&CanonicalValue::Map(request_fields))?;
    let request = CreateHistoryRecoveryRequestCommand::new(
        Sha256Digest::hash_domain(
            b"test-history-recovery-request\0",
            request_id.to_string().as_bytes(),
        ),
        request_id,
        owner.identity_id,
        candidate_device_id,
        candidate_public,
        recipient_key,
        observed_head,
        issued_at,
        expires_at,
        DeviceEnrollmentCapability::new(capability_bytes)?,
        candidate_signature,
        exact_request,
    )?;
    let request_digest = request.request_digest();
    let created = DeviceEnrollmentRepository
        .create_history_recovery_request(store, request, issued_at)
        .await?;
    assert_eq!(created.challenge().challenge_id(), request_id);

    let device_add = device_add(
        &owner.root,
        &candidate,
        owner.identity_id,
        candidate_device_id,
        encryption_seed,
        observed_head.hash(),
        observed_head.sequence().get() + 1,
        NOW + 2,
    )?;
    let approval = DeviceEnrollmentApprovalCommand::new(
        Sha256Digest::hash_domain(
            b"test-history-recovery-approval\0",
            request_id.to_string().as_bytes(),
        ),
        request_id,
        DeviceEnrollmentCapability::new(capability_bytes)?,
        observed_head.hash(),
        device_add.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        DeviceEnrollmentRepository
            .approve(
                store,
                approval,
                DeviceSessionCredential::new(owner.session_id, owner.session_secret)?,
                UtcMillis::new(NOW + 2)?,
            )
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let approved_head = IdentityLogRepository::new()
        .load(store, owner.identity_id)
        .await?
        .ok_or("identity missing after V40 recovery approval")?
        .head();

    let challenge = DeviceSessionRepository
        .issue_challenge(
            store,
            owner.identity_id,
            candidate_device_id,
            [candidate_seed.wrapping_add(1); 32],
            AUDIENCE,
            UtcMillis::new(NOW + 3)?,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let session_proof = signature(
        &candidate,
        &device_session_proof_input(
            owner.identity_id,
            candidate_device_id,
            challenge.challenge_id(),
            challenge.nonce(),
            AUDIENCE,
            session_id,
            session_secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    assert!(matches!(
        DeviceSessionRepository
            .complete(
                store,
                &DeviceSessionCompletionCommand::new(
                    Sha256Digest::hash_domain(
                        b"test-history-recovery-session\0",
                        request_id.to_string().as_bytes(),
                    ),
                    owner.identity_id,
                    candidate_device_id,
                    challenge.challenge_id(),
                    session_id,
                    *challenge.nonce(),
                    session_secret,
                    session_proof,
                )?,
                UtcMillis::new(NOW + 3)?,
            )
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(RecoveredDevice {
        active: ActiveDevice {
            root: SigningKey::from_bytes(&owner.root.to_bytes()),
            recovery: SigningKey::from_bytes(&owner.recovery.to_bytes()),
            identity_id: owner.identity_id,
            device_id: candidate_device_id,
            session_id,
            session_secret,
        },
        request_id,
        request_digest,
        approved_head,
        recipient_package_digest: Sha256Digest::hash_domain(
            b"dirextalk.history-recovery-recipient-package.v1\0",
            recipient_key.as_bytes(),
        ),
    })
}

async fn create_ready_history_attachment(
    store: &MailboxPgStore,
    owner: &ActiveDevice,
    seed: u8,
    expires_at: UtcMillis,
    now: UtcMillis,
) -> Result<(Uuid, Sha256Digest), Box<dyn Error>> {
    let object_id = Uuid::now_v7();
    let ciphertext = vec![0x7d; 64];
    let chunk_digest = Sha256Digest::from_bytes(Sha256::digest(&ciphertext).into());
    let mut manifest_bytes = b"DTXA1".to_vec();
    manifest_bytes.extend_from_slice(&1_u16.to_be_bytes());
    manifest_bytes.extend_from_slice(&0_u16.to_be_bytes());
    manifest_bytes.extend_from_slice(&u32::try_from(ciphertext.len())?.to_be_bytes());
    manifest_bytes.extend_from_slice(chunk_digest.as_bytes());
    manifest_bytes.extend_from_slice(&17_u32.to_be_bytes());
    manifest_bytes.extend_from_slice(&[0x7e; 17]);
    let manifest = AttachmentManifest::parse(manifest_bytes.clone()).unwrap();
    let manifest_digest = Sha256Digest::from_bytes(Sha256::digest(&manifest_bytes).into());
    let upload = AttachmentCapability::new([seed; 32]);
    let read = AttachmentCapability::new([seed.wrapping_add(1); 32]);
    let credential = DeviceSessionCredential::new(owner.session_id, owner.session_secret)?;
    assert_eq!(
        AttachmentRepository
            .create(
                store,
                &credential,
                &AttachmentCreate {
                    object_id,
                    owner_identity_id: owner.identity_id,
                    owner_device_id: owner.device_id,
                    manifest_digest,
                    chunk_count: 1,
                    ciphertext_bytes: u64::try_from(ciphertext.len())?,
                    expires_at,
                },
                &upload,
                &read,
                now,
            )
            .await
            .unwrap(),
        AttachmentStatus::Created,
    );
    assert_eq!(
        AttachmentRepository
            .put_chunk(
                store,
                object_id,
                0,
                &upload,
                Sha256Digest::hash_domain(
                    b"test-history-recovery-attachment-chunk\0",
                    object_id.as_bytes(),
                ),
                chunk_digest,
                &ciphertext,
                UtcMillis::new(now.get() + 1)?,
            )
            .await
            .unwrap(),
        AttachmentStatus::Created,
    );
    assert_eq!(
        AttachmentRepository
            .finalize(
                store,
                object_id,
                &upload,
                &manifest,
                UtcMillis::new(now.get() + 2)?,
            )
            .await
            .unwrap(),
        AttachmentStatus::Ready,
    );
    Ok((object_id, manifest_digest))
}

async fn enroll_active_device(
    store: &IdentityPgStore,
    root_seed: u8,
    recovery_seed: u8,
    device_seed: u8,
    session_secret: [u8; 32],
) -> Result<ActiveDevice, Box<dyn Error>> {
    enroll_active_device_at(
        store,
        root_seed,
        recovery_seed,
        device_seed,
        session_secret,
        NOW,
    )
    .await
}

async fn enroll_active_device_at(
    store: &IdentityPgStore,
    root_seed: u8,
    recovery_seed: u8,
    device_seed: u8,
    session_secret: [u8; 32],
    now: i64,
) -> Result<ActiveDevice, Box<dyn Error>> {
    let root = SigningKey::from_bytes(&[root_seed; 32]);
    let recovery = SigningKey::from_bytes(&[recovery_seed; 32]);
    let device = SigningKey::from_bytes(&[device_seed; 32]);
    let genesis = genesis(&root, &recovery, now - 1_000)?;
    let identity_id = genesis.identity_id();
    let repository = IdentityLogRepository::new();
    let bootstrap = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-mailbox-bootstrap\0", &[root_seed]),
        None,
        genesis.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append_bootstrap(store, &bootstrap, UtcMillis::new(now - 800)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let device_id = DeviceId::new();
    let initial = device_add(
        &root,
        &device,
        identity_id,
        device_id,
        device_seed.wrapping_add(1),
        genesis.entry_hash()?,
        2,
        now - 700,
    )?;
    assert!(matches!(
        repository
            .append_initial_device(
                store,
                Sha256Digest::hash_domain(b"test-mailbox-initial\0", &[root_seed]),
                genesis.entry_hash()?,
                initial.to_deterministic_cbor()?,
                UtcMillis::new(now - 500)?,
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
            UtcMillis::new(now)?,
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
            .complete(store, &completion, UtcMillis::new(now)?)
            .await?,
        DeviceSessionOutcome::Issued(_)
    ));
    Ok(ActiveDevice {
        root,
        recovery,
        identity_id,
        device_id,
        session_id,
        session_secret,
    })
}

async fn add_active_device(
    store: &IdentityPgStore,
    owner: &ActiveDevice,
    device_seed: u8,
    session_secret: [u8; 32],
) -> Result<ActiveDevice, Box<dyn Error>> {
    let repository = IdentityLogRepository::new();
    let head = repository
        .load(store, owner.identity_id)
        .await?
        .ok_or("identity missing before second device add")?
        .head();
    let device = SigningKey::from_bytes(&[device_seed; 32]);
    let device_id = DeviceId::new();
    let event = device_add(
        &owner.root,
        &device,
        owner.identity_id,
        device_id,
        device_seed.wrapping_add(1),
        head.hash(),
        head.sequence().get() + 1,
        NOW - 100,
    )?;
    let command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-mailbox-additional-device\0", &[device_seed]),
        Some(head),
        event.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append(store, &command, UtcMillis::new(NOW - 50)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let challenge = DeviceSessionRepository
        .issue_challenge(
            store,
            owner.identity_id,
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
            owner.identity_id,
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
        Sha256Digest::hash_domain(b"test-mailbox-additional-session\0", &[device_seed]),
        owner.identity_id,
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
        root: SigningKey::from_bytes(&owner.root.to_bytes()),
        recovery: SigningKey::from_bytes(&owner.recovery.to_bytes()),
        identity_id: owner.identity_id,
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

#[allow(clippy::too_many_arguments)]
fn device_history_grant_body(
    identity_id: IdentityId,
    new_device_id: DeviceId,
    identity_head: Sha256Digest,
    authorization_kind: u64,
    authorizer_id: String,
    authorizer: &SigningKey,
    new_device: &SigningKey,
    history_seed: u8,
    pop_seed: u8,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let unsigned = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(new_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            identity_head.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(5), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Bytes(vec![history_seed; 32]),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Unsigned(authorization_kind),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(authorizer_id),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Bytes(vec![pop_seed; 32]),
        ),
        (
            CanonicalValue::Unsigned(10),
            UtcMillis::new(NOW)?.to_canonical_value(),
        ),
    ]);
    let unsigned_bytes = encode_deterministic_cbor(&unsigned)?;
    let mut grant_input = b"dirextalk.device-history-grant.v1\0".to_vec();
    grant_input.extend_from_slice(&unsigned_bytes);
    let mut pop_input = b"dirextalk.device-history-grant-pop.v1\0".to_vec();
    pop_input.extend_from_slice(&unsigned_bytes);
    let CanonicalValue::Map(mut fields) = unsigned else {
        unreachable!()
    };
    fields.push((
        CanonicalValue::Unsigned(11),
        signature(authorizer, &grant_input).to_canonical_value(),
    ));
    fields.push((
        CanonicalValue::Unsigned(12),
        signature(new_device, &pop_input).to_canonical_value(),
    ));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(fields))?)
}

#[allow(clippy::too_many_arguments)]
fn device_history_grant_body_v2(
    idempotency_key: &str,
    identity_id: IdentityId,
    request_id: DeviceEnrollmentChallengeId,
    recovery_request_digest: Sha256Digest,
    approved_head_hash: Sha256Digest,
    candidate_device_id: DeviceId,
    provider_device_id: DeviceId,
    authority_id: &str,
    mailbox_id: MailboxId,
    envelope_id: EnvelopeId,
    provider_highwater: u64,
    recipient_package_digest: Sha256Digest,
    attachment_digest: Sha256Digest,
    opaque_offer: &[u8],
    granted_at: UtcMillis,
    expires_at: UtcMillis,
    provider: &SigningKey,
    authority: &SigningKey,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let idempotency_key_hash = Sha256Digest::hash_domain(
        b"dirextalk.mailbox-http-history-grant-idempotency-key.v2\0",
        idempotency_key.as_bytes(),
    );
    let offer_digest =
        Sha256Digest::hash_domain(b"dirextalk.device-history-offer.v2\0", opaque_offer);
    let unsigned = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(request_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            recovery_request_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(5),
            approved_head_hash.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(candidate_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(provider_device_id.to_string()),
        ),
        (CanonicalValue::Unsigned(8), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Text(authority_id.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(10),
            CanonicalValue::Text(mailbox_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(11),
            CanonicalValue::Text(envelope_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(12),
            CanonicalValue::Unsigned(provider_highwater),
        ),
        (
            CanonicalValue::Unsigned(13),
            CanonicalValue::Unsigned(provider_highwater + 1),
        ),
        (
            CanonicalValue::Unsigned(14),
            recipient_package_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(15),
            attachment_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(16),
            offer_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(17),
            granted_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(18),
            expires_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(19),
            idempotency_key_hash.to_canonical_value(),
        ),
    ]);
    let unsigned_bytes = encode_deterministic_cbor(&unsigned)?;
    let mut provider_input = b"dirextalk.device-history-grant-provider.v2\0".to_vec();
    provider_input.extend_from_slice(&unsigned_bytes);
    let mut authority_input = b"dirextalk.device-history-grant-authority.v2\0".to_vec();
    authority_input.extend_from_slice(&unsigned_bytes);
    let CanonicalValue::Map(mut fields) = unsigned else {
        unreachable!()
    };
    fields.push((
        CanonicalValue::Unsigned(20),
        signature(provider, &provider_input).to_canonical_value(),
    ));
    fields.push((
        CanonicalValue::Unsigned(21),
        signature(authority, &authority_input).to_canonical_value(),
    ));
    fields.push((
        CanonicalValue::Unsigned(22),
        CanonicalValue::Bytes(opaque_offer.to_vec()),
    ));
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(fields))?)
}

fn assert_v3_single_envelope(
    bytes: &[u8],
    expected_highwater: u64,
    expected_floor: u64,
    expected_envelope: EnvelopeId,
    expected_ciphertext: &[u8],
) -> Result<(), Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("V3 pull receipt not a map".into());
    };
    if fields.len() != 6
        || fields[3].1 != CanonicalValue::Unsigned(expected_highwater)
        || fields[4].1 != CanonicalValue::Unsigned(expected_floor)
    {
        return Err("V3 pull head/floor mismatch".into());
    }
    let CanonicalValue::Array(segments) = &fields[5].1 else {
        return Err("V3 pull segments missing".into());
    };
    let [CanonicalValue::Map(segment)] = segments.as_slice() else {
        return Err("V3 pull must contain one envelope".into());
    };
    if segment.len() != 5
        || segment[0].1 != CanonicalValue::Unsigned(1)
        || segment[1].1 != CanonicalValue::Unsigned(expected_highwater)
        || segment[2].1 != CanonicalValue::Text(expected_envelope.to_string())
        || segment[3].1 != CanonicalValue::Bytes(expected_ciphertext.to_vec())
    {
        return Err("V3 pull envelope mismatch".into());
    }
    Ok(())
}

fn account_read_cursor_write_body(
    conversation_digest: Sha256Digest,
    base_revision: u64,
    revision: u64,
    encrypted_cursor: &[u8],
    identity_head: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            conversation_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Unsigned(base_revision),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Unsigned(revision),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Bytes(encrypted_cursor.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(6),
            identity_head.to_canonical_value(),
        ),
    ]))?)
}

fn account_read_cursor_query_body(
    conversation_digest: Sha256Digest,
) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            conversation_digest.to_canonical_value(),
        ),
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

#[allow(clippy::too_many_arguments)]
async fn send_v2(
    app: axum::Router,
    path: &str,
    content_type: &str,
    idempotency_key: Option<&str>,
    session_id: DeviceSessionId,
    session_secret: [u8; 32],
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::AUTHORIZATION,
            device_session_authorization(session_id, session_secret),
        );
    if let Some(key) = idempotency_key {
        request = request.header("idempotency-key", key);
    }
    app.oneshot(request.body(Body::from(body))?)
        .await
        .map_err(Into::into)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the test helper mirrors the complete public mailbox HTTP request boundary"
)]
async fn send_network_mailbox_request(
    client: &reqwest::Client,
    method: reqwest::Method,
    origin: &str,
    path: &str,
    content_type: &str,
    idempotency_key: Option<&str>,
    authorization: String,
    body: Vec<u8>,
) -> Result<reqwest::Response, Box<dyn Error>> {
    let mut request = client
        .request(method, format!("{origin}{path}"))
        .header(header::CONTENT_TYPE.as_str(), content_type)
        .header(header::AUTHORIZATION.as_str(), authorization)
        .body(body);
    if let Some(idempotency_key) = idempotency_key {
        request = request.header("idempotency-key", idempotency_key);
    }
    Ok(request.send().await?)
}

fn assert_network_content_type(response: &reqwest::Response, expected: &str) {
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE.as_str())
            .and_then(|value| value.to_str().ok()),
        Some(expected)
    );
}

async fn assert_network_mailbox_error(
    response: reqwest::Response,
    expected_status: StatusCode,
    expected_code: &str,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(response.status(), expected_status);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL.as_str())
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS.as_str())
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    let body: serde_json::Value = serde_json::from_slice(&response.bytes().await?)?;
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_str),
        Some(expected_code)
    );
    Ok(())
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
    encryption_seed: u8,
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
        DeviceEncryptionPublicKey::try_from([encryption_seed; 32])?,
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
