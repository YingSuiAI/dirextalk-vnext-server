#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one HTTP/PostgreSQL workflow proves exact replay, capability separation, H+1, invalidation, revocation, and response redaction together"
)]
async fn catalog_http_workflow_is_exact_capability_gated_and_fail_closed()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let clock = Arc::new(TestClock::new(5_000));
    let app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            store.clone(),
            clock.clone(),
            AUDIENCE,
        ),
    );
    let identity_repository = IdentityLogRepository::new();
    let enrollment_repository = DeviceEnrollmentRepository;

    let root = key(1);
    let recovery = key(2);
    let authority = key(3);
    let provider = key(4);
    let candidate = key(5);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let head1 = committed(
        identity_repository
            .append(&store, &append_command(1, None, &genesis)?, at(1_001))
            .await?,
    )?;
    let authority_device = DeviceId::from_str(AUTHORITY_DEVICE)?;
    let authority_add = device_add(
        &root,
        identity_id,
        authority_device,
        &authority,
        33,
        2,
        head1.hash(),
        1_010,
    );
    let head2 = committed(
        identity_repository
            .append(
                &store,
                &append_command(2, Some(head1), &authority_add)?,
                at(1_011),
            )
            .await?,
    )?;
    let provider_device = DeviceId::from_str(PROVIDER_DEVICE)?;
    let provider_add = device_add(
        &root,
        identity_id,
        provider_device,
        &provider,
        44,
        3,
        head2.hash(),
        1_020,
    );
    let head3 = committed(
        identity_repository
            .append(
                &store,
                &append_command(3, Some(head2), &provider_add)?,
                at(1_021),
            )
            .await?,
    )?;
    let authority_session = session(
        &store,
        identity_id,
        authority_device,
        &authority,
        11,
        at(2_000),
    )
    .await?;
    let provider_session = session(
        &store,
        identity_id,
        provider_device,
        &provider,
        12,
        at(2_000),
    )
    .await?;

    let runtime_acl: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT
             has_table_privilege(current_user,'identity.recovery_scope_catalogs','SELECT,INSERT'),
             NOT has_table_privilege(current_user,'identity.recovery_scope_catalogs','UPDATE,DELETE'),
             has_table_privilege(current_user,'identity.recovery_scope_catalog_preparations','SELECT,INSERT'),
             NOT has_table_privilege(current_user,'identity.recovery_scope_catalog_preparations','DELETE')",
    )
    .fetch_one(harness.identity_runtime_pool())
    .await?;
    assert_eq!(runtime_acl, (true, true, true, true));

    let catalog = catalog_body(identity_id, head3, &authority, safe(1), None, [31; 32])?;
    let (first, second) = tokio::join!(
        send_catalog(
            app.clone(),
            "catalog-publish-0001",
            &authority_session,
            1,
            RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
            catalog.clone(),
        ),
        send_catalog(
            app.clone(),
            "catalog-publish-0001",
            &authority_session,
            1,
            RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
            catalog.clone(),
        ),
    );
    let first = first?;
    let second = second?;
    assert_created_and_replayed(&first, &second);
    assert_catalog_headers(&first, RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE);
    let first_head = to_bytes(first.into_body(), 16_384).await?.to_vec();
    let second_head = to_bytes(second.into_body(), 16_384).await?.to_vec();
    assert_eq!(first_head, second_head);
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 0, 0));
    let catalog_head_digest = Sha256Digest::hash_domain(
        dtx_identity_persistence::CATALOG_HEAD_DIGEST_DOMAIN,
        &first_head,
    );

    let changed = catalog_body(identity_id, head3, &authority, safe(1), None, [32; 32])?;
    let changed_response = send_catalog(
        app.clone(),
        "catalog-publish-0001",
        &authority_session,
        1,
        RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
        changed,
    )
    .await?;
    assert_error(
        changed_response,
        StatusCode::CONFLICT,
        "IDEMPOTENCY_CONFLICT",
    )
    .await?;
    let gap = catalog_body(
        identity_id,
        head3,
        &authority,
        safe(3),
        Some(catalog_head_digest),
        [33; 32],
    )?;
    let gap_response = send_catalog(
        app.clone(),
        "catalog-publish-gap",
        &authority_session,
        3,
        RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
        gap,
    )
    .await?;
    assert_error(
        gap_response,
        StatusCode::CONFLICT,
        "RECOVERY_CATALOG_CONFLICT",
    )
    .await?;
    let wrong_media = send_catalog(
        app.clone(),
        "catalog-publish-media",
        &authority_session,
        2,
        "application/cbor",
        catalog.clone(),
    )
    .await?;
    assert_error(
        wrong_media,
        StatusCode::UNPROCESSABLE_ENTITY,
        "RECOVERY_CATALOG_INVALID",
    )
    .await?;
    let oversized = send_catalog(
        app.clone(),
        "catalog-publish-oversized",
        &authority_session,
        2,
        RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
        vec![0; MAX_RECOVERY_SCOPE_CATALOG_COMMAND_BYTES + 1],
    )
    .await?;
    assert_error(
        oversized,
        StatusCode::UNPROCESSABLE_ENTITY,
        "RECOVERY_CATALOG_INVALID",
    )
    .await?;
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 0, 0));

    let candidate_device = DeviceId::from_str(CANDIDATE_DEVICE)?;
    let enrollment_capability = [41; 32];
    let challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([42; 32]),
                identity_id,
                candidate_device,
                public(&candidate),
                DeviceEncryptionPublicKey::try_from([55; 32])?,
                DeviceEnrollmentCapability::new(enrollment_capability)?,
            )?,
            at(4_000),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(challenge) = challenge else {
        return Err("ordinary enrollment challenge must be new".into());
    };
    let response_capability = [61; 32];
    let equal_capability_preparation = preparation_body(
        challenge.challenge_id(),
        identity_id,
        candidate_device,
        &candidate,
        [55; 32],
        head3,
        enrollment_capability,
    )?;
    let equal_capability_response = send_preparation(
        app.clone(),
        "catalog-preparation-equal-capabilities",
        enrollment_capability,
        enrollment_capability,
        equal_capability_preparation,
    )
    .await?;
    assert_error(
        equal_capability_response,
        StatusCode::UNAUTHORIZED,
        "RECOVERY_RESPONSE_CAPABILITY_REJECTED",
    )
    .await?;
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 0, 0));
    let preparation = preparation_body(
        challenge.challenge_id(),
        identity_id,
        candidate_device,
        &candidate,
        [55; 32],
        head3,
        response_capability,
    )?;
    let (prepare_first, prepare_second) = tokio::join!(
        send_preparation(
            app.clone(),
            "catalog-preparation-0001",
            enrollment_capability,
            response_capability,
            preparation.clone(),
        ),
        send_preparation(
            app.clone(),
            "catalog-preparation-0001",
            enrollment_capability,
            response_capability,
            preparation.clone(),
        ),
    );
    let prepare_first = prepare_first?;
    let prepare_second = prepare_second?;
    assert_created_and_replayed(&prepare_first, &prepare_second);
    assert_catalog_headers(&prepare_first, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 1, 0));

    let wrong_capability = send_status(app.clone(), challenge.challenge_id(), [62; 32]).await?;
    assert_error(
        wrong_capability,
        StatusCode::UNAUTHORIZED,
        "RECOVERY_RESPONSE_CAPABILITY_REJECTED",
    )
    .await?;
    let pending = send_status(app.clone(), challenge.challenge_id(), response_capability).await?;
    assert_eq!(pending.status(), StatusCode::OK);
    assert_catalog_headers(&pending, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    assert_redacted_status(pending, 1).await?;

    let invalid_provider = provider_body(
        challenge.challenge_id(),
        catalog_head_digest,
        authority_device,
        &authority,
        Sha256Digest::from_bytes([99; 32]),
        [55; 32],
    )?;
    let invalid_provider_response = send_provider_response(
        app.clone(),
        "catalog-provider-invalid",
        &authority_session,
        challenge.challenge_id(),
        invalid_provider,
    )
    .await?;
    assert_error(
        invalid_provider_response,
        StatusCode::PRECONDITION_FAILED,
        "RECOVERY_PREPARATION_INVALIDATED",
    )
    .await?;
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 1, 0));

    let candidate_add = device_add(
        &root,
        identity_id,
        candidate_device,
        &candidate,
        55,
        4,
        head3.hash(),
        5_200,
    );
    let approval = DeviceEnrollmentApprovalCommand::new(
        Sha256Digest::from_bytes([71; 32]),
        challenge.challenge_id(),
        DeviceEnrollmentCapability::new(enrollment_capability)?,
        head3.hash(),
        candidate_add.to_deterministic_cbor()?,
    )?;
    let head4 = committed(
        enrollment_repository
            .approve(
                &store,
                approval,
                DeviceSessionCredential::new(
                    provider_session.session_id,
                    provider_session.session_secret,
                )?,
                at(5_201),
            )
            .await?,
    )?;
    clock.set(5_300);
    let provider_response_body = provider_body(
        challenge.challenge_id(),
        catalog_head_digest,
        provider_device,
        &provider,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [55; 32],
    )?;
    let (provider_first, provider_second) = tokio::join!(
        send_provider_response(
            app.clone(),
            "catalog-provider-0001",
            &provider_session,
            challenge.challenge_id(),
            provider_response_body.clone(),
        ),
        send_provider_response(
            app.clone(),
            "catalog-provider-0001",
            &provider_session,
            challenge.challenge_id(),
            provider_response_body.clone(),
        ),
    );
    let provider_first = provider_first?;
    let provider_second = provider_second?;
    assert_eq!(provider_first.status(), StatusCode::OK);
    assert_eq!(provider_second.status(), StatusCode::OK);
    assert_catalog_headers(&provider_first, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    assert_catalog_headers(&provider_second, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    assert_eq!(
        to_bytes(provider_first.into_body(), 1_100_000).await?,
        to_bytes(provider_second.into_body(), 1_100_000).await?
    );
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 1, 1));
    let ready = send_status(app.clone(), challenge.challenge_id(), response_capability).await?;
    assert_eq!(ready.status(), StatusCode::OK);
    assert_catalog_headers(&ready, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    let ready_bytes = to_bytes(ready.into_body(), 1_100_000).await?;
    let CanonicalValue::Map(ready_fields) = decode_deterministic_cbor(&ready_bytes)? else {
        return Err("ready status must be a map".into());
    };
    assert_eq!(ready_fields.len(), 6);
    assert_eq!(ready_fields[2].1, CanonicalValue::Unsigned(2));
    assert_eq!(
        ready_fields[3].1,
        decode_deterministic_cbor(&provider_response_body)?
    );
    let ready_replay = send_preparation(
        app.clone(),
        "catalog-preparation-0001",
        enrollment_capability,
        response_capability,
        preparation.clone(),
    )
    .await?;
    assert_eq!(ready_replay.status(), StatusCode::OK);
    assert_catalog_headers(&ready_replay, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    assert_eq!(
        to_bytes(ready_replay.into_body(), 1_100_000).await?,
        ready_bytes
    );

    clock.set(5_400);
    let rotated = catalog_body(
        identity_id,
        head4,
        &authority,
        safe(2),
        Some(catalog_head_digest),
        [34; 32],
    )?;
    let rotated_response = send_catalog(
        app.clone(),
        "catalog-publish-0002",
        &authority_session,
        2,
        RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
        rotated,
    )
    .await?;
    assert_eq!(rotated_response.status(), StatusCode::CREATED);
    assert_catalog_headers(&rotated_response, RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE);
    let rotated_head = to_bytes(rotated_response.into_body(), 16_384)
        .await?
        .to_vec();
    let rotated_head_digest = Sha256Digest::hash_domain(
        dtx_identity_persistence::CATALOG_HEAD_DIGEST_DOMAIN,
        &rotated_head,
    );
    let invalidated =
        send_status(app.clone(), challenge.challenge_id(), response_capability).await?;
    assert_eq!(invalidated.status(), StatusCode::PRECONDITION_FAILED);
    let invalidated_bytes = assert_redacted_status(invalidated, 4).await?;
    let invalidated_replay = send_preparation(
        app.clone(),
        "catalog-preparation-0001",
        enrollment_capability,
        response_capability,
        preparation.clone(),
    )
    .await?;
    assert_eq!(invalidated_replay.status(), StatusCode::OK);
    assert_catalog_headers(
        &invalidated_replay,
        RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE,
    );
    assert_eq!(
        to_bytes(invalidated_replay.into_body(), 1_100_000).await?,
        invalidated_bytes
    );

    let cancelled_candidate = key(6);
    let cancelled_candidate_device = DeviceId::from_str(SECOND_CANDIDATE_DEVICE)?;
    let cancelled_enrollment_capability = [91; 32];
    let cancelled_challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([92; 32]),
                identity_id,
                cancelled_candidate_device,
                public(&cancelled_candidate),
                DeviceEncryptionPublicKey::try_from([66; 32])?,
                DeviceEnrollmentCapability::new(cancelled_enrollment_capability)?,
            )?,
            at(5_401),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(cancelled_challenge) = cancelled_challenge else {
        return Err("cancelled enrollment challenge must be new".into());
    };
    let cancelled_response_capability = [93; 32];
    let cancelled_preparation = preparation_body(
        cancelled_challenge.challenge_id(),
        identity_id,
        cancelled_candidate_device,
        &cancelled_candidate,
        [66; 32],
        head4,
        cancelled_response_capability,
    )?;
    let prepared = send_preparation(
        app.clone(),
        "catalog-preparation-cancelled",
        cancelled_enrollment_capability,
        cancelled_response_capability,
        cancelled_preparation,
    )
    .await?;
    assert_eq!(prepared.status(), StatusCode::CREATED);
    enrollment_repository
        .cancel(
            &store,
            cancelled_challenge.challenge_id(),
            DeviceEnrollmentCapability::new(cancelled_enrollment_capability)?,
            at(5_402),
        )
        .await?;
    clock.set(5_403);
    let cancelled_status = send_status(
        app.clone(),
        cancelled_challenge.challenge_id(),
        cancelled_response_capability,
    )
    .await?;
    assert_eq!(cancelled_status.status(), StatusCode::PRECONDITION_FAILED);
    assert_redacted_status(cancelled_status, 4).await?;
    let cancelled_provider = provider_body(
        cancelled_challenge.challenge_id(),
        rotated_head_digest,
        provider_device,
        &provider,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [66; 32],
    )?;
    let cancelled_provider_response = send_provider_response(
        app.clone(),
        "catalog-provider-cancelled",
        &provider_session,
        cancelled_challenge.challenge_id(),
        cancelled_provider,
    )
    .await?;
    assert_error(
        cancelled_provider_response,
        StatusCode::GONE,
        "RECOVERY_PREPARATION_REVOKED",
    )
    .await?;
    assert_eq!(recovery_rows(&harness, identity_id).await?, (2, 2, 1));

    let revoke = signed_event(
        &root,
        identity_id,
        5,
        Some(head4.hash()),
        5_500,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: provider_device,
        },
    );
    committed(
        identity_repository
            .append(
                &store,
                &append_command(81, Some(head4), &revoke)?,
                at(5_501),
            )
            .await?,
    )?;
    clock.set(5_600);
    let revoked_provider = send_provider_response(
        app.clone(),
        "catalog-provider-0001",
        &provider_session,
        challenge.challenge_id(),
        provider_response_body,
    )
    .await?;
    assert_error(
        revoked_provider,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;
    assert_eq!(recovery_rows(&harness, identity_id).await?, (2, 2, 1));

    clock.set(200_000);
    let expired = send_status(app.clone(), challenge.challenge_id(), response_capability).await?;
    assert_eq!(expired.status(), StatusCode::GONE);
    let expired_bytes = assert_redacted_status(expired, 3).await?;
    let expired_replay = send_preparation(
        app.clone(),
        "catalog-preparation-0001",
        enrollment_capability,
        response_capability,
        preparation,
    )
    .await?;
    assert_eq!(expired_replay.status(), StatusCode::OK);
    assert_catalog_headers(&expired_replay, RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE);
    assert_eq!(
        to_bytes(expired_replay.into_body(), 1_100_000).await?,
        expired_bytes
    );

    sqlx::query("REVOKE SELECT ON identity.recovery_scope_catalogs FROM dtx_identity_runtime")
        .execute(harness.admin_pool())
        .await?;
    clock.set(6_000);
    let unavailable = send_status(app, challenge.challenge_id(), response_capability).await?;
    assert_error(
        unavailable,
        StatusCode::SERVICE_UNAVAILABLE,
        "IDENTITY_SERVICE_UNAVAILABLE",
    )
    .await?;
    assert_eq!(recovery_rows(&harness, identity_id).await?, (2, 2, 1));
    Ok(())
}
