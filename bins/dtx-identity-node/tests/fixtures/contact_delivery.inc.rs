#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one HTTP/PostgreSQL boundary test protects opaque delivery, exact replay, revocation, and device-revocation admission together"
)]
async fn opaque_contact_delivery_is_replay_safe_and_revocable() -> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            store.clone(),
            Arc::new(FixedClock(2_000)),
            AUDIENCE,
        ),
    );
    let owner = enroll_active_device(&store, 81, 82, 83, [84; 32]).await?;

    let invite_secret = [85_u8; 32];
    let invite_id = InviteCapabilityId::new();
    let invite = contact_invite_body(&owner, invite_id, invite_secret, 2)?;
    let first_invite = send_contact_invite(
        app.clone(),
        "contact-invite-0001",
        &owner,
        invite_secret,
        invite.clone(),
    )
    .await?;
    assert_eq!(first_invite.status(), StatusCode::CREATED);
    assert_eq!(first_invite.headers()[header::CACHE_CONTROL], "no-store");
    let first_invite_receipt = to_bytes(first_invite.into_body(), 16_384).await?;
    let replay_invite = send_contact_invite(
        app.clone(),
        "contact-invite-0001",
        &owner,
        invite_secret,
        invite,
    )
    .await?;
    assert_eq!(replay_invite.status(), StatusCode::CREATED);
    assert_eq!(
        to_bytes(replay_invite.into_body(), 16_384).await?,
        first_invite_receipt
    );

    let receipt_secret = [86_u8; 32];
    let request_id = RequestId::new();
    let sealed_request = b"opaque:a-device-proof-and-contact-request";
    let request = contact_request_body(
        request_id,
        invite_id,
        owner.identity_id,
        owner.device_id,
        receipt_secret,
        sealed_request,
    )?;
    let first_submit = send_contact_request(app.clone(), invite_secret, request.clone()).await?;
    assert_eq!(first_submit.status(), StatusCode::CREATED);
    let first_submit_receipt = to_bytes(first_submit.into_body(), 16_384).await?;
    let replay_submit = send_contact_request(app.clone(), invite_secret, request).await?;
    assert_eq!(replay_submit.status(), StatusCode::CREATED);
    assert_eq!(
        to_bytes(replay_submit.into_body(), 16_384).await?,
        first_submit_receipt
    );
    let use_count: i16 =
        sqlx::query_scalar("SELECT use_count FROM identity.contact_invites WHERE invite_id=$1")
            .bind(invite_id.as_uuid())
            .fetch_one(harness.identity_runtime_pool())
            .await?;
    assert_eq!(
        use_count, 1,
        "an exact replay must not spend the invite twice"
    );

    let pending = send_contact_pending(app.clone(), &owner).await?;
    assert_eq!(pending.status(), StatusCode::OK);
    assert_eq!(
        pending.headers()[header::CONTENT_TYPE],
        CONTACT_PENDING_CONTENT_TYPE
    );
    let pending = to_bytes(pending.into_body(), 200_000).await?;
    assert!(
        pending
            .windows(sealed_request.len())
            .any(|window| window == sealed_request),
        "the node must relay the opaque request without interpreting it"
    );
    let receipt_hash = contact_receipt_capability_hash(&receipt_secret);
    assert!(
        pending
            .windows(receipt_hash.as_bytes().len())
            .any(|window| window == receipt_hash.as_bytes()),
        "the target needs the non-authorizing receipt hash to reconstruct HPKE AAD"
    );

    let sealed_delivery = b"opaque:peer-mailbox-descriptor+origin-pin+claimable-key-package";
    let review = contact_review_body(
        request_id,
        invite_id,
        owner.identity_id,
        owner.device_id,
        sealed_delivery,
    )?;
    let accepted = send_contact_review(
        app.clone(),
        "contact-review-0001",
        &owner,
        request_id,
        review.clone(),
    )
    .await?;
    assert_eq!(accepted.status(), StatusCode::OK);
    let accepted_receipt = to_bytes(accepted.into_body(), 300_000).await?;
    let accepted_replay = send_contact_review(
        app.clone(),
        "contact-review-0001",
        &owner,
        request_id,
        review,
    )
    .await?;
    assert_eq!(accepted_replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(accepted_replay.into_body(), 300_000).await?,
        accepted_receipt
    );
    let poll = send_contact_receipt(app.clone(), request_id, receipt_secret).await?;
    assert_eq!(poll.status(), StatusCode::OK);
    assert_eq!(
        poll.headers()[header::CONTENT_TYPE],
        CONTACT_RECEIPT_CONTENT_TYPE
    );
    let poll_body = to_bytes(poll.into_body(), 300_000).await?;
    assert_eq!(poll_body, accepted_receipt);
    assert!(
        poll_body
            .windows(sealed_delivery.len())
            .any(|window| window == sealed_delivery)
    );
    let poll_replay = send_contact_receipt(app.clone(), request_id, receipt_secret).await?;
    assert_eq!(to_bytes(poll_replay.into_body(), 300_000).await?, poll_body);
    let outbox_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity.contact_delivery_outbox WHERE request_id=$1",
    )
    .bind(request_id.as_uuid())
    .fetch_one(harness.identity_runtime_pool())
    .await?;
    assert_eq!(outbox_count, 1);

    let device_revoked_invite_id = InviteCapabilityId::new();
    let device_revoked_secret = [87_u8; 32];
    let device_revoked_invite =
        contact_invite_body(&owner, device_revoked_invite_id, device_revoked_secret, 2)?;
    assert_eq!(
        send_contact_invite(
            app.clone(),
            "contact-invite-device-revoke",
            &owner,
            device_revoked_secret,
            device_revoked_invite,
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    let pending_before_revoke_id = RequestId::new();
    let pending_before_revoke_secret = [88_u8; 32];
    let pending_before_revoke_request = contact_request_body(
        pending_before_revoke_id,
        device_revoked_invite_id,
        owner.identity_id,
        owner.device_id,
        pending_before_revoke_secret,
        b"pending-before-device-revoke",
    )?;
    assert_eq!(
        send_contact_request(
            app.clone(),
            device_revoked_secret,
            pending_before_revoke_request.clone(),
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    revoke_active_device(&store, &owner).await?;
    let revoked_receipt = send_contact_receipt(
        app.clone(),
        pending_before_revoke_id,
        pending_before_revoke_secret,
    )
    .await?;
    assert_eq!(revoked_receipt.status(), StatusCode::OK);
    let revoked_receipt_body = to_bytes(revoked_receipt.into_body(), 300_000).await?;
    let submit_replay_after_revoke = send_contact_request(
        app.clone(),
        device_revoked_secret,
        pending_before_revoke_request,
    )
    .await?;
    assert_eq!(submit_replay_after_revoke.status(), StatusCode::CREATED);
    assert_eq!(
        to_bytes(submit_replay_after_revoke.into_body(), 300_000).await?,
        revoked_receipt_body,
        "an admitted request must replay its terminal receipt after target-device revocation"
    );
    let revoked_state: i16 =
        sqlx::query_scalar("SELECT state FROM identity.contact_requests WHERE request_id=$1")
            .bind(pending_before_revoke_id.as_uuid())
            .fetch_one(harness.identity_runtime_pool())
            .await?;
    assert_eq!(
        revoked_state, 6,
        "poll must durably expose device revocation"
    );
    let blocked = send_contact_request(
        app,
        device_revoked_secret,
        contact_request_body(
            RequestId::new(),
            device_revoked_invite_id,
            owner.identity_id,
            owner.device_id,
            [89; 32],
            b"must-not-be-admitted-after-device-revoke",
        )?,
    )
    .await?;
    assert_eq!(blocked.status(), StatusCode::CONFLICT);
    let blocked_uses: i16 =
        sqlx::query_scalar("SELECT use_count FROM identity.contact_invites WHERE invite_id=$1")
            .bind(device_revoked_invite_id.as_uuid())
            .fetch_one(harness.identity_runtime_pool())
            .await?;
    assert_eq!(blocked_uses, 1);
    Ok(())
}
