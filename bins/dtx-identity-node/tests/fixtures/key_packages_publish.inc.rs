#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one HTTP/PostgreSQL boundary test keeps opaque package binding, one-time claim, response-loss replay, and revocation rechecks coherent"
)]
async fn opaque_key_packages_are_device_bound_idempotent_and_claimed_once()
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
    let publisher = enroll_active_device(&store, 61, 62, 63, [64; 32]).await?;
    let requester = enroll_active_device(&store, 71, 72, 73, [74; 32]).await?;

    let zero_head_package_id = KeyPackageId::new();
    let zero_head_publish = key_package_publish_body(
        &publisher.device,
        publisher.identity_id,
        publisher.device_id,
        zero_head_package_id,
        SafeUint::new(0)?,
        publisher.head_hash,
        UtcMillis::new(600_000)?,
        &[0x00],
    )?;
    let zero_head_response = send_key_package_publish(
        app.clone(),
        "key-package-publish-zero-head",
        publisher.session_id,
        publisher.session_secret,
        zero_head_package_id,
        zero_head_publish,
    )
    .await?;
    assert_eq!(
        zero_head_response.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_safe_error(zero_head_response, "KEY_PACKAGE_INVALID").await?;

    let invalid_signature_package_id = KeyPackageId::new();
    let mut invalid_signature_publish = key_package_publish_body(
        &publisher.device,
        publisher.identity_id,
        publisher.device_id,
        invalid_signature_package_id,
        publisher.head_sequence,
        publisher.head_hash,
        UtcMillis::new(600_000)?,
        &[0x01],
    )?;
    let signature_tail = invalid_signature_publish
        .last_mut()
        .ok_or("key package signature test body was unexpectedly empty")?;
    *signature_tail ^= 1;
    let invalid_signature_response = send_key_package_publish(
        app.clone(),
        "key-package-publish-invalid-signature",
        publisher.session_id,
        publisher.session_secret,
        invalid_signature_package_id,
        invalid_signature_publish,
    )
    .await?;
    assert_eq!(
        invalid_signature_response.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_safe_error(invalid_signature_response, "KEY_PACKAGE_INVALID").await?;

    let package_id = KeyPackageId::new();
    let expires_at = UtcMillis::new(600_000)?;
    let package_bytes = vec![0xd0, 0x0d, 0xfe, 0xed];
    let publish_body = key_package_publish_body(
        &publisher.device,
        publisher.identity_id,
        publisher.device_id,
        package_id,
        publisher.head_sequence,
        publisher.head_hash,
        expires_at,
        &package_bytes,
    )?;
    let publish_response = send_key_package_publish(
        app.clone(),
        "key-package-publish-0001",
        publisher.session_id,
        publisher.session_secret,
        package_id,
        publish_body.clone(),
    )
    .await?;
    assert_eq!(publish_response.status(), StatusCode::CREATED);
    assert_eq!(
        publish_response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(KEY_PACKAGE_PUBLISH_RECEIPT_CONTENT_TYPE)
    );
    let publish_receipt = to_bytes(publish_response.into_body(), 16_384)
        .await?
        .to_vec();
    let publish_replay = send_key_package_publish(
        app.clone(),
        "key-package-publish-0001",
        publisher.session_id,
        publisher.session_secret,
        package_id,
        publish_body.clone(),
    )
    .await?;
    assert_eq!(publish_replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(publish_replay.into_body(), 16_384).await?.to_vec(),
        publish_receipt
    );

    let changed_publish = key_package_publish_body(
        &publisher.device,
        publisher.identity_id,
        publisher.device_id,
        package_id,
        publisher.head_sequence,
        publisher.head_hash,
        expires_at,
        &[0x00, 0x01, 0x02],
    )?;
    let publish_conflict = send_key_package_publish(
        app.clone(),
        "key-package-publish-0001",
        publisher.session_id,
        publisher.session_secret,
        package_id,
        changed_publish,
    )
    .await?;
    assert_eq!(publish_conflict.status(), StatusCode::CONFLICT);
    assert_safe_error(publish_conflict, "IDEMPOTENCY_CONFLICT").await?;

    let claim_body = key_package_claim_body(publisher.identity_id, publisher.device_id)?;
    let (first_claim, second_claim) = tokio::join!(
        send_key_package_claim(
            app.clone(),
            "key-package-claim-0001",
            requester.session_id,
            requester.session_secret,
            claim_body.clone(),
        ),
        send_key_package_claim(
            app.clone(),
            "key-package-claim-0001",
            requester.session_id,
            requester.session_secret,
            claim_body.clone(),
        ),
    );
    let first_claim = first_claim?;
    let second_claim = second_claim?;
    assert!(
        (first_claim.status() == StatusCode::CREATED && second_claim.status() == StatusCode::OK)
            || (first_claim.status() == StatusCode::OK
                && second_claim.status() == StatusCode::CREATED)
    );
    assert_eq!(
        first_claim
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(KEY_PACKAGE_CLAIM_RECEIPT_CONTENT_TYPE)
    );
    assert_eq!(
        to_bytes(first_claim.into_body(), 131_072).await?.to_vec(),
        publish_body
    );
    assert_eq!(
        to_bytes(second_claim.into_body(), 131_072).await?.to_vec(),
        publish_body
    );
    let claim_count: i64 = sqlx::query_scalar("SELECT count(*) FROM identity.key_package_claims")
        .fetch_one(harness.identity_runtime_pool())
        .await?;
    assert_eq!(claim_count, 1);

    let changed_claim = key_package_claim_body(requester.identity_id, requester.device_id)?;
    let claim_conflict = send_key_package_claim(
        app.clone(),
        "key-package-claim-0001",
        requester.session_id,
        requester.session_secret,
        changed_claim,
    )
    .await?;
    assert_eq!(claim_conflict.status(), StatusCode::CONFLICT);
    assert_safe_error(claim_conflict, "IDEMPOTENCY_CONFLICT").await?;

    let exhausted = send_key_package_claim(
        app.clone(),
        "key-package-claim-0002",
        requester.session_id,
        requester.session_secret,
        claim_body.clone(),
    )
    .await?;
    assert_eq!(exhausted.status(), StatusCode::NOT_FOUND);
    assert_safe_error(exhausted, "KEY_PACKAGE_UNAVAILABLE").await?;

    let revoked_target_package_id = KeyPackageId::new();
    let revoked_target_package = key_package_publish_body(
        &publisher.device,
        publisher.identity_id,
        publisher.device_id,
        revoked_target_package_id,
        publisher.head_sequence,
        publisher.head_hash,
        expires_at,
        &[0x01, 0x23, 0x45, 0x67],
    )?;
    let published_before_target_revoke = send_key_package_publish(
        app.clone(),
        "key-package-publish-0002",
        publisher.session_id,
        publisher.session_secret,
        revoked_target_package_id,
        revoked_target_package,
    )
    .await?;
    assert_eq!(published_before_target_revoke.status(), StatusCode::CREATED);

    revoke_active_device(&store, &publisher).await?;
    let revoked_target_claim = send_key_package_claim(
        app.clone(),
        "key-package-claim-0003",
        requester.session_id,
        requester.session_secret,
        claim_body.clone(),
    )
    .await?;
    assert_eq!(revoked_target_claim.status(), StatusCode::NOT_FOUND);
    assert_safe_error(revoked_target_claim, "KEY_PACKAGE_UNAVAILABLE").await?;

    revoke_active_device(&store, &requester).await?;
    let revoked_requester_claim = send_key_package_claim(
        app,
        "key-package-claim-0001",
        requester.session_id,
        requester.session_secret,
        claim_body,
    )
    .await?;
    assert_eq!(revoked_requester_claim.status(), StatusCode::UNAUTHORIZED);
    assert_safe_error(revoked_requester_claim, "DEVICE_AUTHENTICATION_FAILED").await?;

    let pruned: i64 = sqlx::query_scalar("SELECT identity.prune_expired_key_packages($1, $2)")
        .bind(1_000_000_i64)
        .bind(16_i32)
        .fetch_one(harness.identity_runtime_pool())
        .await?;
    assert_eq!(pruned, 2);
    let retained: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
             (SELECT count(*) FROM identity.key_packages),
             (SELECT count(*) FROM identity.key_package_publish_claims),
             (SELECT count(*) FROM identity.key_package_claims),
             (SELECT count(*) FROM identity.key_package_claim_receipts)",
    )
    .fetch_one(harness.identity_runtime_pool())
    .await?;
    assert_eq!(retained, (0, 0, 0, 0));
    Ok(())
}
