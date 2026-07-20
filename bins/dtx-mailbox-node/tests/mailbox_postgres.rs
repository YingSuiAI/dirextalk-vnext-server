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
use dtx_domain::{Clock, ClockError, DeviceId, DeviceSessionId, EnvelopeId, IdentityId, MailboxId};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_persistence::{
    DEVICE_SESSION_SECRET_HASH_DOMAIN, DeviceSessionCompletionCommand, DeviceSessionCredential,
    DeviceSessionOutcome, DeviceSessionRepository, IdentityAppendCommand, IdentityAppendOutcome,
    IdentityLogRepository, IdentityPgStore, device_session_proof_input,
};
use dtx_mailbox::{
    AttachmentCapability, AttachmentCreate, AttachmentError, AttachmentManifest,
    AttachmentRepository, AttachmentStatus, MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN,
    MailboxPersistenceError, MailboxPgStore, MailboxRegistrationCommand, MailboxRepository,
};
use dtx_mailbox_node::{
    DEVICE_HISTORY_GRANT_V1_CONTENT_TYPE, DEVICE_HISTORY_GRANT_V1_PATH,
    DEVICE_SESSION_AUTHORIZATION_SCHEME, IDENTITY_MAILBOX_ACK_V2_CONTENT_TYPE,
    IDENTITY_MAILBOX_ACK_V2_PATH, IDENTITY_MAILBOX_PULL_V2_CONTENT_TYPE,
    IDENTITY_MAILBOX_PULL_V2_PATH, MAILBOX_ACK_CONTENT_TYPE, MAILBOX_ACK_PATH_TEMPLATE,
    MAILBOX_ACK_RECEIPT_CONTENT_TYPE, MAILBOX_CAPABILITY_AUTHORIZATION_SCHEME,
    MAILBOX_ENQUEUE_PATH_TEMPLATE, MAILBOX_ENVELOPE_CONTENT_TYPE,
    MAILBOX_ENVELOPE_RECEIPT_CONTENT_TYPE, MAILBOX_PULL_CONTENT_TYPE, MAILBOX_PULL_PATH_TEMPLATE,
    MAILBOX_PULL_RECEIPT_CONTENT_TYPE, MAILBOX_REGISTER_CONTENT_TYPE,
    MAILBOX_REGISTER_PATH_TEMPLATE, MAILBOX_REGISTER_RECEIPT_CONTENT_TYPE, MailboxNodeState,
    mailbox_router_with_state,
};
use dtx_realtime_sync::{
    HEARTBEAT_INTERVAL_MILLIS, LEASE_TTL_MILLIS, RealtimeSyncError, RealtimeSyncStore, ReplayPage,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgConnectOptions;
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

    let pull_body = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Unsigned(0)),
        (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(100)),
    ]))?;
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
    sqlx::query(
        "UPDATE messaging.device_history_grants SET revoked_at_ms=$3 \
         WHERE identity_id=$1 AND new_device_id=$2",
    )
    .bind(owner.identity_id.to_string())
    .bind(*second.device_id.as_uuid())
    .bind(NOW + 1)
    .execute(harness.admin_pool())
    .await?;
    assert_eq!(
        send_v2(
            app,
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
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store.clone(),
        Arc::new(FixedClock(NOW)),
    ));
    let owner = enroll_active_device(&identity_store, 121, 122, 123, [124; 32]).await?;
    let credential = DeviceSessionCredential::new(owner.session_id, owner.session_secret)?;

    let mailbox_id = MailboxId::new();
    let capability = [125; 32];
    let registration_body = mailbox_registration_body(
        mailbox_id,
        owner.identity_id,
        owner.device_id,
        capability,
        UtcMillis::new(EXPIRY)?,
    )?;
    let registration = MailboxRegistrationCommand::new(
        Sha256Digest::hash_domain(b"test-realtime-register\0", b"register"),
        mailbox_id,
        owner.identity_id,
        owner.device_id,
        Sha256Digest::hash_domain(MAILBOX_WRITE_CAPABILITY_HASH_DOMAIN, &capability),
        UtcMillis::new(EXPIRY)?,
        registration_body,
    )?;
    MailboxRepository
        .register(
            &mailbox_store,
            &credential,
            &registration,
            UtcMillis::new(NOW)?,
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
            mailbox_envelope_body(envelope_id, b"opaque", UtcMillis::new(EXPIRY)?)?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );

    let first = realtime_store
        .acquire(&credential, SafeUint::new(0)?, UtcMillis::new(NOW)?)
        .await?;
    let current = realtime_store
        .acquire(&credential, SafeUint::new(0)?, UtcMillis::new(NOW + 1)?)
        .await?;
    assert_eq!(current.fence.get(), first.fence.get() + 1);
    assert!(matches!(
        realtime_store
            .replay(
                &credential,
                first,
                SafeUint::new(0)?,
                UtcMillis::new(NOW + 2)?
            )
            .await,
        Err(RealtimeSyncError::StaleLease)
    ));

    let ReplayPage::Events { highwater, events } = realtime_store
        .replay(
            &credential,
            current,
            SafeUint::new(0)?,
            UtcMillis::new(NOW + 2)?,
        )
        .await?
    else {
        panic!("durable event must replay before expiry");
    };
    assert_eq!(highwater.get(), 1);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].cursor.get(), 1);
    realtime_store
        .acknowledge(
            &credential,
            current,
            SafeUint::new(1)?,
            UtcMillis::new(NOW + 3)?,
        )
        .await?;

    let renewed = realtime_store
        .heartbeat(
            &credential,
            current,
            UtcMillis::new(NOW + HEARTBEAT_INTERVAL_MILLIS)?,
        )
        .await?;
    assert_eq!(
        renewed.expires_at.get(),
        NOW + HEARTBEAT_INTERVAL_MILLIS + LEASE_TTL_MILLIS
    );
    assert!(matches!(
        realtime_store
            .replay(
                &credential,
                renewed,
                SafeUint::new(1)?,
                UtcMillis::new(renewed.expires_at.get())?,
            )
            .await,
        Err(RealtimeSyncError::StaleLease)
    ));

    sqlx::query(
        "UPDATE realtime.journal SET created_at_ms=$2,expires_at_ms=$3 \
         WHERE identity_id=$1 AND cursor=1",
    )
    .bind(owner.identity_id.to_string())
    .bind(NOW - 2)
    .bind(NOW - 1)
    .execute(harness.admin_pool())
    .await?;
    let catch_up_lease = realtime_store
        .acquire(&credential, SafeUint::new(0)?, UtcMillis::new(NOW + 4)?)
        .await?;
    assert!(matches!(
        realtime_store
            .replay(
                &credential,
                catch_up_lease,
                SafeUint::new(0)?,
                UtcMillis::new(NOW + 4)?,
            )
            .await?,
        ReplayPage::CatchUpRequired { highwater } if highwater.get() == 1
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
