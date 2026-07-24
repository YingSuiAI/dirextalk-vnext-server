#[path = "mailbox_support.rs"]
mod common;
use common::*;

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
