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
    let genesis_event = genesis(&root, &recovery);
    let identity_id = genesis_event.identity_id();
    let head1 = committed(
        identity_repository
            .append(&store, &append_command(1, None, &genesis_event)?, at(1_001))
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
    for (case, accept) in [
        ("catalog-publish-missing-accept", None),
        ("catalog-publish-wrong-accept", Some("application/cbor")),
    ] {
        let replay = send_catalog_custom(
            app.clone(),
            "catalog-publish-0001",
            &authority_session,
            1,
            RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
            accept,
            None,
            catalog.clone(),
        )
        .await?;
        assert_eq!(replay.status(), StatusCode::OK, "{case}");
        assert_catalog_headers(&replay, RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE);
        assert_eq!(to_bytes(replay.into_body(), 16_384).await?, first_head);
    }
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
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "RECOVERY_HANDOFF_UNSUPPORTED_MEDIA_TYPE",
    )
    .await?;
    let oversized = send_catalog(
        app.clone(),
        "catalog-publish-oversized",
        &authority_session,
        2,
        RECOVERY_SCOPE_CATALOG_CONTENT_TYPE,
        vec![0; MAX_RECOVERY_SCOPE_CATALOG_UPLOAD_BYTES + 1],
    )
    .await?;
    assert_error(
        oversized,
        StatusCode::PAYLOAD_TOO_LARGE,
        "RECOVERY_HANDOFF_TOO_LARGE",
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
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?,
        safe(1),
        catalog_head_digest,
        "catalog-preparation-equal-capabilities",
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
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?,
        safe(1),
        catalog_head_digest,
        "catalog-preparation-0001",
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
    assert_catalog_headers(&prepare_first, RECOVERY_SCOPE_CATALOG_PREPARATION_RECEIPT_CONTENT_TYPE);
    let preparation_receipt_bytes = to_bytes(prepare_first.into_body(), 16_384).await?.to_vec();
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 1, 0));
    for (case, accept) in [
        ("preparation-missing-accept", None),
        ("preparation-wrong-accept", Some("application/cbor")),
    ] {
        let replay = send_preparation_custom(
            app.clone(),
            "catalog-preparation-0001",
            enrollment_capability,
            response_capability,
            RECOVERY_SCOPE_CATALOG_PREPARATION_CONTENT_TYPE,
            accept,
            None,
            preparation.clone(),
        )
        .await?;
        assert_eq!(replay.status(), StatusCode::OK, "{case}");
        assert_catalog_headers(&replay, RECOVERY_SCOPE_CATALOG_PREPARATION_RECEIPT_CONTENT_TYPE);
        assert_eq!(to_bytes(replay.into_body(), 16_384).await?, preparation_receipt_bytes);
    }
    let preparation_wrong_media = send_preparation_custom(
        app.clone(),
        "catalog-preparation-wrong-media",
        enrollment_capability,
        response_capability,
        "application/cbor",
        None,
        None,
        preparation.clone(),
    )
    .await?;
    assert_error(
        preparation_wrong_media,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "RECOVERY_HANDOFF_UNSUPPORTED_MEDIA_TYPE",
    )
    .await?;
    let preparation_oversized = send_preparation_custom(
        app.clone(),
        "catalog-preparation-oversized",
        enrollment_capability,
        response_capability,
        RECOVERY_SCOPE_CATALOG_PREPARATION_CONTENT_TYPE,
        None,
        None,
        vec![0; MAX_RECOVERY_SCOPE_CATALOG_PREPARATION_BYTES + 1],
    )
    .await?;
    assert_error(
        preparation_oversized,
        StatusCode::PAYLOAD_TOO_LARGE,
        "RECOVERY_HANDOFF_TOO_LARGE",
    )
    .await?;

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
    for (case, accept) in [
        ("status-missing-accept", None),
        ("status-wrong-accept", Some("application/cbor")),
    ] {
        let rejected = send_status_custom(
            app.clone(),
            challenge.challenge_id(),
            response_capability,
            None,
            accept,
            Vec::new(),
        )
        .await?;
        assert_eq!(rejected.status(), StatusCode::NOT_ACCEPTABLE, "{case}");
        assert_catalog_headers(&rejected, "application/json");
    }

    let get_with_content_type = send_status_custom(
        app.clone(),
        challenge.challenge_id(),
        response_capability,
        Some(RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE),
        None,
        Vec::new(),
    )
    .await?;
    assert_error(
        get_with_content_type,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "RECOVERY_HANDOFF_UNSUPPORTED_MEDIA_TYPE",
    )
    .await?;
    let get_with_body = send_status_custom(
        app.clone(),
        challenge.challenge_id(),
        response_capability,
        None,
        Some(RECOVERY_SCOPE_CATALOG_STATUS_CONTENT_TYPE),
        vec![0],
    )
    .await?;
    assert_error(
        get_with_body,
        StatusCode::UNAUTHORIZED,
        "RECOVERY_RESPONSE_CAPABILITY_REJECTED",
    )
    .await?;

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
    let candidate_add_bytes = candidate_add.to_deterministic_cbor()?;
    // Keep one duplicate candidate card open while the approved V4 request
    // is attempted. Admission must reject before inserting any request row;
    // cancelling this card then allows the exact request to proceed.
    let active_candidate_capability = [74; 32];
    let active_candidate = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([73; 32]),
                identity_id,
                candidate_device,
                public(&candidate),
                DeviceEncryptionPublicKey::try_from([55; 32])?,
                DeviceEnrollmentCapability::new(active_candidate_capability)?,
            )?,
            at(5_200),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(active_candidate) = active_candidate else {
        return Err("duplicate candidate challenge must be new".into());
    };
    let approval = DeviceEnrollmentApprovalCommand::new(
        Sha256Digest::from_bytes([71; 32]),
        challenge.challenge_id(),
        DeviceEnrollmentCapability::new(enrollment_capability)?,
        head3.hash(),
        candidate_add_bytes.clone(),
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
    let invalid_provider = provider_body(
        challenge.challenge_id(),
        identity_id,
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?,
        safe(1),
        catalog_head_digest,
        &preparation,
        &first_head,
        head3,
        head4,
        candidate_device,
        [55; 32],
        &candidate_add_bytes,
        DeviceId::from_str(SECOND_CANDIDATE_DEVICE)?,
        &key(6),
        authority_device,
        &authority,
        "catalog-provider-invalid",
        at(5_300),
        at(200_000),
    )?;
    let invalid_provider_response = send_provider_response(
        app.clone(),
        "catalog-provider-invalid",
        &provider_session,
        challenge.challenge_id(),
        invalid_provider.clone(),
    )
    .await?;
    assert_error(
        invalid_provider_response,
        StatusCode::FORBIDDEN,
        "RECOVERY_PROVIDER_MISMATCH",
    )
    .await?;
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 1, 0));
    let provider_response_body = provider_body(
        challenge.challenge_id(),
        identity_id,
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?,
        safe(1),
        catalog_head_digest,
        &preparation,
        &first_head,
        head3,
        head4,
        candidate_device,
        [55; 32],
        &candidate_add_bytes,
        provider_device,
        &provider,
        authority_device,
        &authority,
        "catalog-provider-0001",
        at(5_300),
        at(200_000),
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
    assert_created_and_replayed(&provider_first, &provider_second);
    assert_catalog_headers(&provider_first, RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE);
    assert_catalog_headers(&provider_second, RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE);
    assert_eq!(
        to_bytes(provider_first.into_body(), 1_100_000).await?,
        to_bytes(provider_second.into_body(), 1_100_000).await?
    );
    assert_eq!(recovery_rows(&harness, identity_id).await?, (1, 1, 1));

    let provider_gate_store = IdentityPgStore::connect(
        harness
            .identity_runtime_options()
            .application_name("catalog-http-provider-gate"),
        1,
    )
    .await?;
    let provider_gate_app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            provider_gate_store,
            clock.clone(),
            AUDIENCE,
        ),
    );
    let status_gate_store = IdentityPgStore::connect(
        harness
            .identity_runtime_options()
            .application_name("catalog-http-status-gate"),
        1,
    )
    .await?;
    let status_gate_app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            status_gate_store,
            clock.clone(),
            AUDIENCE,
        ),
    );
    let mut identity_fence = harness.admin_pool().begin().await?;
    let lock_key = i64::from_be_bytes(identity_id.digest_bytes()[..8].try_into()?);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut *identity_fence)
        .await?;
    let gate = async {
        let waiter_gate = wait_for_exact_advisory_waiters(
            harness.admin_pool(),
            lock_key,
            &["catalog-http-provider-gate", "catalog-http-status-gate"],
        )
        .await;
        identity_fence.rollback().await?;
        waiter_gate?;
        Ok::<(), Box<dyn Error>>(())
    };
    let ((provider_response, status_response), gate_result) = tokio::join!(
        async {
            tokio::join!(
                send_provider_response(
                    provider_gate_app,
                    "catalog-provider-0001",
                    &provider_session,
                    challenge.challenge_id(),
                    provider_response_body.clone(),
                ),
                send_status(status_gate_app, challenge.challenge_id(), response_capability),
            )
        },
        gate,
    );
    gate_result?;
    assert_eq!(provider_response?.status(), StatusCode::OK);
    assert_eq!(status_response?.status(), StatusCode::OK);

    let wrong_media = send_provider_response_custom(
        app.clone(),
        "catalog-provider-wrong-media",
        &provider_session,
        challenge.challenge_id(),
        "application/cbor",
        Some(RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE),
        None,
        provider_response_body.clone(),
    )
    .await?;
    assert_error(
        wrong_media,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "RECOVERY_HANDOFF_UNSUPPORTED_MEDIA_TYPE",
    )
    .await?;
    let wrong_accept = send_provider_response_custom(
        app.clone(),
        "catalog-provider-wrong-accept",
        &provider_session,
        challenge.challenge_id(),
        RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
        Some("application/cbor"),
        None,
        provider_response_body.clone(),
    )
    .await?;
    assert_error(wrong_accept, StatusCode::NOT_ACCEPTABLE, "RECOVERY_HANDOFF_NOT_ACCEPTABLE")
        .await?;
    let missing_accept = send_provider_response_custom(
        app.clone(),
        "catalog-provider-missing-accept",
        &provider_session,
        challenge.challenge_id(),
        RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
        None,
        None,
        provider_response_body.clone(),
    )
    .await?;
    assert_error(missing_accept, StatusCode::NOT_ACCEPTABLE, "RECOVERY_HANDOFF_NOT_ACCEPTABLE")
        .await?;
    let wrong_key = send_provider_response_custom(
        app.clone(),
        "catalog-provider-0001",
        &authority_session,
        challenge.challenge_id(),
        RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
        Some(RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE),
        None,
        provider_response_body.clone(),
    )
    .await?;
    assert_error(
        wrong_key,
        StatusCode::FORBIDDEN,
        "RECOVERY_PROVIDER_MISMATCH",
    )
    .await?;
    let invalid_credential = Session {
        session_id: provider_session.session_id,
        session_secret: [99; 32],
    };
    let invalid_credential_response = send_provider_response_custom(
        app.clone(),
        "catalog-provider-0001",
        &invalid_credential,
        challenge.challenge_id(),
        RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
        Some(RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE),
        None,
        provider_response_body.clone(),
    )
    .await?;
    assert_error(
        invalid_credential_response,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;
    let nonexistent_request = DeviceEnrollmentChallengeId::new();
    let nonexistent_body = provider_body(
        nonexistent_request,
        identity_id,
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?,
        safe(1),
        catalog_head_digest,
        &preparation,
        &first_head,
        head3,
        head4,
        candidate_device,
        [55; 32],
        &candidate_add_bytes,
        provider_device,
        &provider,
        authority_device,
        &authority,
        "catalog-provider-nonexistent",
        at(5_300),
        at(200_000),
    )?;
    let nonexistent_invalid_credential = send_provider_response_custom(
        app.clone(),
        "catalog-provider-nonexistent",
        &invalid_credential,
        nonexistent_request,
        RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
        Some(RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE),
        None,
        nonexistent_body,
    )
    .await?;
    assert_error(
        nonexistent_invalid_credential,
        StatusCode::UNAUTHORIZED,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;
    let wrong_body = send_provider_response_custom(
        app.clone(),
        "catalog-provider-wrong-body",
        &provider_session,
        challenge.challenge_id(),
        RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
        Some(RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE),
        None,
        vec![0xff],
    )
    .await?;
    assert_error(wrong_body, StatusCode::UNPROCESSABLE_ENTITY, "EXACT_CBOR_INVALID")
        .await?;
    let declared_small_stream_large = send_provider_response_custom(
        app.clone(),
        "catalog-provider-stream-large",
        &provider_session,
        challenge.challenge_id(),
        RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
        Some(RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE),
        Some("1"),
        vec![0; MAX_RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_BYTES + 1],
    )
    .await?;
    assert_error(
        declared_small_stream_large,
        StatusCode::PAYLOAD_TOO_LARGE,
        "RECOVERY_HANDOFF_TOO_LARGE",
    )
    .await?;
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
    assert_catalog_headers(
        &ready_replay,
        RECOVERY_SCOPE_CATALOG_PREPARATION_RECEIPT_CONTENT_TYPE,
    );
    assert_eq!(
        to_bytes(ready_replay.into_body(), 1_100_000).await?,
        preparation_receipt_bytes
    );

    // The V4 request uses only artifacts accepted by the production Catalog
    // workflow above: the signed H+1 DeviceAdd, the persisted preparation and
    // provider response, and the canonical signed Catalog head.
    let request_idempotency = "history-recovery-v4-0001";
    let v4_request = history_recovery_request_v4_body(
        challenge.challenge_id(),
        identity_id,
        candidate_device,
        &candidate,
        [55; 32],
        head3,
        head4,
        &candidate_add_bytes,
        &preparation,
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?,
        &first_head,
        catalog_head_digest,
        response_capability,
        request_idempotency,
    )?;

    // The V4 boundary is fail-closed before repository admission.  Every
    // malformed header/body shape below must share the safe error envelope and
    // leave the immutable request table empty.
    let valid_v4_headers = || {
        history_recovery_request_v4_headers(
            Some(HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE),
            Some(HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE),
            Some(request_idempotency),
            Some(&enrollment_capability),
            Some(&response_capability),
            None,
            None,
            None,
        )
    };
    let wrong_bound_enrollment_capability = [74; 32];
    let mut header_rejections = vec![
        (
            "content-type",
            {
                let mut headers = valid_v4_headers();
                headers.insert(header::CONTENT_TYPE, "application/cbor".parse()?);
                headers
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        ),
        (
            "accept",
            {
                let mut headers = valid_v4_headers();
                headers.insert(header::ACCEPT, "application/cbor".parse()?);
                headers
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        ),
        (
            "missing enrollment capability",
            history_recovery_request_v4_headers(
                Some(HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE),
                Some(HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE),
                Some(request_idempotency),
                None,
                Some(&response_capability),
                None,
                None,
                None,
            ),
            StatusCode::UNAUTHORIZED,
            "DEVICE_ENROLLMENT_CAPABILITY_INVALID",
        ),
        (
            "invalid enrollment capability",
            {
                let mut headers = valid_v4_headers();
                headers.insert(
                    DEVICE_ENROLLMENT_CAPABILITY_HEADER,
                    "not-a-capability".parse()?,
                );
                headers
            },
            StatusCode::UNAUTHORIZED,
            "DEVICE_ENROLLMENT_CAPABILITY_INVALID",
        ),
        (
            "wrong-bound enrollment capability",
            history_recovery_request_v4_headers(
                Some(HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE),
                Some(HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE),
                Some(request_idempotency),
                Some(&wrong_bound_enrollment_capability),
                Some(&response_capability),
                None,
                None,
                None,
            ),
            StatusCode::UNAUTHORIZED,
            "DEVICE_ENROLLMENT_CAPABILITY_INVALID",
        ),
        (
            "missing response capability",
            history_recovery_request_v4_headers(
                Some(HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE),
                Some(HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE),
                Some(request_idempotency),
                Some(&enrollment_capability),
                None,
                None,
                None,
                None,
            ),
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        ),
        (
            "short idempotency key",
            history_recovery_request_v4_headers(
                Some(HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE),
                Some(HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE),
                Some("short"),
                Some(&enrollment_capability),
                Some(&response_capability),
                None,
                None,
                None,
            ),
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        ),
        (
            "noncanonical idempotency key",
            history_recovery_request_v4_headers(
                Some(HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE),
                Some(HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE),
                Some("history recovery 0001"),
                Some(&enrollment_capability),
                Some(&response_capability),
                None,
                None,
                None,
            ),
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        ),
        (
            "oversize idempotency key",
            history_recovery_request_v4_headers(
                Some(HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE),
                Some(HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE),
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                Some(&enrollment_capability),
                Some(&response_capability),
                None,
                None,
                None,
            ),
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        ),
        (
            "content encoding",
            history_recovery_request_v4_headers(
                Some(HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE),
                Some(HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE),
                Some(request_idempotency),
                Some(&enrollment_capability),
                Some(&response_capability),
                None,
                Some("gzip"),
                None,
            ),
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        ),
        (
            "if-match forbidden",
            history_recovery_request_v4_headers(
                Some(HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE),
                Some(HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE),
                Some(request_idempotency),
                Some(&enrollment_capability),
                Some(&response_capability),
                None,
                None,
                Some("\"head\""),
            ),
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        ),
        (
            "authorization forbidden",
            history_recovery_request_v4_headers(
                Some(HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE),
                Some(HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE),
                Some(request_idempotency),
                Some(&enrollment_capability),
                Some(&response_capability),
                Some("DTX-Device malformed"),
                None,
                None,
            ),
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        ),
    ];
    let mut duplicate_content_type = valid_v4_headers();
    duplicate_content_type.append(
        header::CONTENT_TYPE,
        HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE.parse()?,
    );
    header_rejections.push((
        "duplicate content-type",
        duplicate_content_type,
        StatusCode::UNPROCESSABLE_ENTITY,
        "DEVICE_ENROLLMENT_INVALID",
    ));
    let mut duplicate_accept = valid_v4_headers();
    duplicate_accept.append(
        header::ACCEPT,
        HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE.parse()?,
    );
    header_rejections.push((
        "duplicate accept",
        duplicate_accept,
        StatusCode::UNPROCESSABLE_ENTITY,
        "DEVICE_ENROLLMENT_INVALID",
    ));
    let mut duplicate_idempotency = valid_v4_headers();
    duplicate_idempotency.append("idempotency-key", request_idempotency.parse()?);
    header_rejections.push((
        "duplicate idempotency-key",
        duplicate_idempotency,
        StatusCode::UNPROCESSABLE_ENTITY,
        "DEVICE_ENROLLMENT_INVALID",
    ));
    for (case, headers, status, code) in header_rejections {
        let response = send_history_recovery_request_v4_custom(
            app.clone(),
            "POST",
            HISTORY_RECOVERY_REQUEST_V4_PATH,
            headers,
            v4_request.clone(),
        )
        .await?;
        assert_error(response, status, code).await?;
        assert_history_recovery_request_rows(
            harness.admin_pool(),
            challenge.challenge_id(),
            0,
        )
        .await
        .map_err(|error| format!("{case}: {error}"))?;
    }
    for (case, body, status, code) in [
        (
            "empty body",
            Vec::new(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        ),
        (
            "malformed cbor",
            vec![0xff],
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        ),
        (
            "noncanonical cbor",
            vec![0xa1, 0x02, 0x01],
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        ),
        (
            "oversize body",
            vec![0; 37_115],
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        ),
    ] {
        let response = send_history_recovery_request_v4_custom(
            app.clone(),
            "POST",
            HISTORY_RECOVERY_REQUEST_V4_PATH,
            valid_v4_headers(),
            body,
        )
        .await?;
        assert_error(response, status, code).await?;
        assert_history_recovery_request_rows(
            harness.admin_pool(),
            challenge.challenge_id(),
            0,
        )
        .await
        .map_err(|error| format!("{case}: {error}"))?;
    }
    for (case, method, path, expected_status) in [
        (
            "wrong method",
            "PUT",
            HISTORY_RECOVERY_REQUEST_V4_PATH,
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            "wrong path",
            "POST",
            "/v4/devices/history-recovery-requests/",
            StatusCode::NOT_FOUND,
        ),
        (
            "version fallback",
            "POST",
            "/v3/devices/history-recovery-requests",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let response = send_history_recovery_request_v4_custom(
            app.clone(),
            method,
            path,
            valid_v4_headers(),
            v4_request.clone(),
        )
        .await?;
        assert_eq!(response.status(), expected_status, "{case}");
        assert_history_recovery_request_rows(
            harness.admin_pool(),
            challenge.challenge_id(),
            0,
        )
        .await?;
    }
    let blocked = send_history_recovery_request_v4(
        app.clone(),
        request_idempotency,
        enrollment_capability,
        response_capability,
        v4_request.clone(),
    )
    .await?;
    assert_error(
        blocked,
        StatusCode::PRECONDITION_FAILED,
        "CANDIDATE_KEY_CHANGED",
    )
    .await?;
    let blocked_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity.history_recovery_requests WHERE request_id=$1",
    )
    .bind(*challenge.challenge_id().as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(blocked_rows, 0);
    let cancellation = cancel_enrollment_challenge(
        app.clone(),
        active_candidate.challenge_id(),
        active_candidate_capability,
    )
    .await?;
    assert_eq!(cancellation.status(), StatusCode::OK);
    // Hold the exact identity advisory lock while four independent HTTP
    // runtimes enter first admission. The gate releases only after every
    // distinct backend PID is observed waiting on that lock; this proves the
    // contenders are real lock waiters rather than an accidental serial test.
    let concurrent_names = [
        "history-v4-concurrent-0",
        "history-v4-concurrent-1",
        "history-v4-concurrent-2",
        "history-v4-concurrent-3",
    ];
    let concurrent_stores = [
        IdentityPgStore::connect(
            harness
                .identity_runtime_options()
                .application_name(concurrent_names[0]),
            1,
        )
        .await?,
        IdentityPgStore::connect(
            harness
                .identity_runtime_options()
                .application_name(concurrent_names[1]),
            1,
        )
        .await?,
        IdentityPgStore::connect(
            harness
                .identity_runtime_options()
                .application_name(concurrent_names[2]),
            1,
        )
        .await?,
        IdentityPgStore::connect(
            harness
                .identity_runtime_options()
                .application_name(concurrent_names[3]),
            1,
        )
        .await?,
    ];
    let concurrent_apps = concurrent_stores.map(|store| {
        identity_bootstrap_router_with_state(
            IdentityBootstrapState::with_clock_and_device_session_audience(
                store,
                clock.clone(),
                AUDIENCE,
            ),
        )
    });
    let lock_key = i64::from_be_bytes(identity_id.digest_bytes()[..8].try_into()?);
    let mut identity_fence = harness.admin_pool().begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut *identity_fence)
        .await?;
    let gate = async {
        let waiter_pids = wait_for_exact_advisory_waiters(
            harness.admin_pool(),
            lock_key,
            &concurrent_names,
        )
        .await?;
        identity_fence.rollback().await?;
        Ok::<Vec<i32>, Box<dyn Error>>(waiter_pids)
    };
    let concurrent_requests = async {
        tokio::join!(
            send_history_recovery_request_v4(
                concurrent_apps[0].clone(),
                request_idempotency,
                enrollment_capability,
                response_capability,
                v4_request.clone(),
            ),
            send_history_recovery_request_v4(
                concurrent_apps[1].clone(),
                request_idempotency,
                enrollment_capability,
                response_capability,
                v4_request.clone(),
            ),
            send_history_recovery_request_v4(
                concurrent_apps[2].clone(),
                request_idempotency,
                enrollment_capability,
                response_capability,
                v4_request.clone(),
            ),
            send_history_recovery_request_v4(
                concurrent_apps[3].clone(),
                request_idempotency,
                enrollment_capability,
                response_capability,
                v4_request.clone(),
            ),
        )
    };
    let ((first, second, third, fourth), waiter_pids) =
        tokio::join!(concurrent_requests, gate);
    let waiter_pids = waiter_pids?;
    assert_eq!(waiter_pids.len(), concurrent_names.len());
    assert_eq!(
        waiter_pids.iter().copied().collect::<std::collections::BTreeSet<_>>().len(),
        concurrent_names.len(),
    );
    let concurrent_responses = vec![first?, second?, third?, fourth?];
    let mut created_count = 0;
    let mut replay_bodies = Vec::new();
    for response in concurrent_responses {
        let status = response.status();
        assert!(status == StatusCode::CREATED || status == StatusCode::OK);
        assert_history_recovery_request_v4_response_headers(
            &response,
            status,
        );
        if status == StatusCode::CREATED {
            created_count += 1;
        }
        replay_bodies.push(to_bytes(response.into_body(), 16_384).await?.to_vec());
    }
    assert_eq!(created_count, 1);
    let v4_receipt = replay_bodies
        .first()
        .cloned()
        .ok_or("concurrent V4 response set is empty")?;
    assert!(replay_bodies.iter().all(|body| body == &v4_receipt));
    assert_history_recovery_request_rows(
        harness.admin_pool(),
        challenge.challenge_id(),
        1,
    )
    .await?;
    let v4_replay = send_history_recovery_request_v4(
        app.clone(),
        request_idempotency,
        enrollment_capability,
        response_capability,
        v4_request.clone(),
    )
    .await?;
    assert_history_recovery_request_v4_response_headers(&v4_replay, StatusCode::OK);
    assert_eq!(to_bytes(v4_replay.into_body(), 16_384).await?, v4_receipt);

    let changed_signed_request = history_recovery_request_v4_with_outer_tamper(
        &v4_request,
        &candidate,
        17,
        at(5_301).to_canonical_value(),
    )?;
    for response in send_four_history_recovery_request_v4(
        &concurrent_apps,
        request_idempotency,
        enrollment_capability,
        response_capability,
        changed_signed_request,
    )
    .await?
    {
        assert_error(
            response,
            StatusCode::CONFLICT,
            "IDEMPOTENCY_CONFLICT",
        )
        .await?;
    }
    for response in send_four_history_recovery_request_v4(
        &concurrent_apps,
        "history-recovery-v4-changed",
        enrollment_capability,
        response_capability,
        v4_request.clone(),
    )
    .await?
    {
        assert_error(
            response,
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        )
        .await?;
    }
    for response in send_four_history_recovery_request_v4(
        &concurrent_apps,
        request_idempotency,
        [74; 32],
        response_capability,
        v4_request.clone(),
    )
    .await?
    {
        assert_error(
            response,
            StatusCode::UNAUTHORIZED,
            "DEVICE_ENROLLMENT_CAPABILITY_INVALID",
        )
        .await?;
    }
    assert_history_recovery_request_rows(
        harness.admin_pool(),
        challenge.challenge_id(),
        1,
    )
    .await?;
    let cancellation_replay = cancel_enrollment_challenge(
        app.clone(),
        active_candidate.challenge_id(),
        active_candidate_capability,
    )
    .await?;
    assert_eq!(cancellation_replay.status(), StatusCode::OK);
    let v4_after_cancellation = send_history_recovery_request_v4(
        app.clone(),
        request_idempotency,
        enrollment_capability,
        response_capability,
        v4_request.clone(),
    )
    .await?;
    assert_eq!(v4_after_cancellation.status(), StatusCode::OK);
    assert_catalog_headers(
        &v4_after_cancellation,
        HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE,
    );
    assert_eq!(
        to_bytes(v4_after_cancellation.into_body(), 16_384).await?,
        v4_receipt
    );
    let v4_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity.history_recovery_requests WHERE request_id=$1",
    )
    .bind(*challenge.challenge_id().as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(v4_rows, 1);
    // Every manifest coordinate is independently authenticated and bound to
    // the accepted Catalog V2 head. Re-sign each mutated outer request so a
    // rejection cannot be attributed merely to the candidate signature.
    for (field, replacement) in [
        (1, CanonicalValue::Unsigned(3)),
        (2, CanonicalValue::Text("not-the-identity".into())),
        (3, CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-0123456789ff".into())),
        (4, CanonicalValue::Unsigned(2)),
        (5, CanonicalValue::Bytes(vec![0])),
        (6, CanonicalValue::Bytes(vec![0; 32])),
        (7, CanonicalValue::Bytes(vec![0; 32])),
        (8, CanonicalValue::Unsigned(2)),
        (9, CanonicalValue::Bytes(vec![0; 32])),
        (10, CanonicalValue::Array(Vec::new())),
    ] {
        let tampered = history_recovery_request_v4_with_manifest_tamper(
            &v4_request,
            &candidate,
            field,
            replacement,
        )?;
        let response = send_history_recovery_request_v4(
            app.clone(),
            request_idempotency,
            enrollment_capability,
            response_capability,
            tampered,
        )
        .await?;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "manifest field {field}",
        );
        assert_error(
            response,
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        )
        .await?;
    }
    let substituted_leaf = history_recovery_request_v4_with_manifest_leaf_substitution(
        &v4_request,
        &candidate,
        [32; 32],
    )?;
    assert_error(
        send_history_recovery_request_v4(
            app.clone(),
            request_idempotency,
            enrollment_capability,
            response_capability,
            substituted_leaf,
        )
        .await?,
        StatusCode::UNPROCESSABLE_ENTITY,
        "DEVICE_ENROLLMENT_INVALID",
    )
    .await?;
    let uppercase_catalog_id = history_recovery_request_v4_with_manifest_tamper(
        &v4_request,
        &candidate,
        3,
        CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-0123456789B1".into()),
    )?;
    assert_error(
        send_history_recovery_request_v4(
            app.clone(),
            request_idempotency,
            enrollment_capability,
            response_capability,
            uppercase_catalog_id,
        )
        .await?,
        StatusCode::UNPROCESSABLE_ENTITY,
        "DEVICE_ENROLLMENT_INVALID",
    )
    .await?;
    assert_history_recovery_request_rows(
        harness.admin_pool(),
        challenge.challenge_id(),
        1,
    )
    .await?;
    let changed_signed_request = history_recovery_request_v4_with_outer_tamper(
        &v4_request,
        &candidate,
        17,
        at(5_301).to_canonical_value(),
    )?;
    assert_error(
        send_history_recovery_request_v4(
            app.clone(),
            request_idempotency,
            enrollment_capability,
            response_capability,
            changed_signed_request,
        )
        .await?,
        StatusCode::CONFLICT,
        "IDEMPOTENCY_CONFLICT",
    )
    .await?;
    for (case, idempotency, response) in [
        ("idempotency", "history-recovery-v4-changed", response_capability),
        ("response-capability", request_idempotency, [62; 32]),
    ] {
        let rejected = send_history_recovery_request_v4(
            app.clone(),
            idempotency,
            enrollment_capability,
            response,
            v4_request.clone(),
        )
        .await?;
        assert_error(
            rejected,
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        )
        .await?;
        assert_eq!(v4_rows, 1, "{case} must not create a request");
    }
    let rows_after_rejections: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity.history_recovery_requests WHERE request_id=$1",
    )
    .bind(*challenge.challenge_id().as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(rows_after_rejections, 1);
    let signature_tamper = history_recovery_request_v4_with_signature_tamper(&v4_request)?;
    assert_error(
        send_history_recovery_request_v4(
            app.clone(),
            request_idempotency,
            enrollment_capability,
            response_capability,
            signature_tamper,
        )
        .await?,
        StatusCode::UNPROCESSABLE_ENTITY,
        "DEVICE_ENROLLMENT_INVALID",
    )
    .await?;

    // DeviceAdd and Preparation are independently bounded and authenticated
    // before any repository state is touched. Recompute each nested digest
    // and the candidate signature so failures reach the intended inner
    // validator rather than the outer envelope check.
    let mut tampered_device_add = candidate_add_bytes.clone();
    *tampered_device_add.last_mut().expect("DeviceAdd is non-empty") ^= 1;
    let mismatched_device_add = device_add(
        &root,
        identity_id,
        DeviceId::from_str(SECOND_CANDIDATE_DEVICE)?,
        &key(6),
        66,
        4,
        head3.hash(),
        5_200,
    )
    .to_deterministic_cbor()?;
    for (_case, payload) in [
        ("DeviceAdd malformed", vec![0xff]),
        ("DeviceAdd signature", tampered_device_add),
        ("DeviceAdd mismatched", mismatched_device_add),
    ] {
        let tampered = history_recovery_request_v4_with_payload_tamper(
            &v4_request,
            &candidate,
            11,
            payload,
        )?;
        let response = send_history_recovery_request_v4(
            app.clone(),
            request_idempotency,
            enrollment_capability,
            response_capability,
            tampered,
        )
        .await?;
        assert_error(
            response,
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        )
        .await?;
    }
    let device_add_digest_mismatch = history_recovery_request_v4_with_outer_tamper(
        &v4_request,
        &candidate,
        12,
        CanonicalValue::Bytes(vec![0; 32]),
    )?;
    assert_error(
        send_history_recovery_request_v4(
            app.clone(),
            request_idempotency,
            enrollment_capability,
            response_capability,
            device_add_digest_mismatch,
        )
        .await?,
        StatusCode::UNPROCESSABLE_ENTITY,
        "DEVICE_ENROLLMENT_INVALID",
    )
    .await?;

    let mut tampered_preparation = preparation.clone();
    *tampered_preparation
        .last_mut()
        .expect("Preparation is non-empty") ^= 1;
    let mismatched_preparation = preparation_body(
        challenge.challenge_id(),
        identity_id,
        DeviceId::from_str(SECOND_CANDIDATE_DEVICE)?,
        &key(6),
        [66; 32],
        head3,
        enrollment_capability,
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?,
        safe(1),
        catalog_head_digest,
        "catalog-preparation-mismatched-candidate",
    )?;
    for (_case, payload) in [
        ("Preparation malformed", vec![0xff]),
        ("Preparation signature", tampered_preparation),
        ("Preparation mismatched", mismatched_preparation),
    ] {
        let tampered = history_recovery_request_v4_with_payload_tamper(
            &v4_request,
            &candidate,
            13,
            payload,
        )?;
        let response = send_history_recovery_request_v4(
            app.clone(),
            request_idempotency,
            enrollment_capability,
            response_capability,
            tampered,
        )
        .await?;
        assert_error(
            response,
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        )
        .await?;
    }
    let preparation_digest_mismatch = history_recovery_request_v4_with_outer_tamper(
        &v4_request,
        &candidate,
        14,
        CanonicalValue::Bytes(vec![0; 32]),
    )?;
    assert_error(
        send_history_recovery_request_v4(
            app.clone(),
            request_idempotency,
            enrollment_capability,
            response_capability,
            preparation_digest_mismatch,
        )
        .await?,
        StatusCode::UNPROCESSABLE_ENTITY,
        "DEVICE_ENROLLMENT_INVALID",
    )
    .await?;
    for (field, value) in [(17, at(4_499)), (18, at(200_001))] {
        let tampered = history_recovery_request_v4_with_outer_tamper(
            &v4_request,
            &candidate,
            field,
            value.to_canonical_value(),
        )?;
        assert_error(
            send_history_recovery_request_v4(
                app.clone(),
                request_idempotency,
                enrollment_capability,
                response_capability,
                tampered,
            )
            .await?,
            StatusCode::UNPROCESSABLE_ENTITY,
            "DEVICE_ENROLLMENT_INVALID",
        )
        .await?;
    }

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
    let v4_drift_replay = send_history_recovery_request_v4(
        app.clone(),
        request_idempotency,
        enrollment_capability,
        response_capability,
        v4_request.clone(),
    )
    .await?;
    assert_eq!(v4_drift_replay.status(), StatusCode::OK);
    assert_catalog_headers(
        &v4_drift_replay,
        HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE,
    );
    assert_eq!(
        to_bytes(v4_drift_replay.into_body(), 16_384).await?,
        v4_receipt
    );
    let invalidated =
        send_status(app.clone(), challenge.challenge_id(), response_capability).await?;
    assert_eq!(invalidated.status(), StatusCode::OK);
    let invalidated_bytes = assert_redacted_status(invalidated, 5).await?;
    let CanonicalValue::Map(invalidated_fields) = decode_deterministic_cbor(&invalidated_bytes)? else {
        return Err("invalidated status must be a map".into());
    };
    assert_eq!(invalidated_fields[4].1, CanonicalValue::Unsigned(2));
    assert_eq!(invalidated_fields[5].1, CanonicalValue::Unsigned(5_400));
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
        RECOVERY_SCOPE_CATALOG_PREPARATION_RECEIPT_CONTENT_TYPE,
    );
    assert_eq!(
        to_bytes(invalidated_replay.into_body(), 1_100_000).await?,
        preparation_receipt_bytes
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
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b3")?,
        safe(2),
        rotated_head_digest,
        "catalog-preparation-cancelled",
    )?;
    let prepared = send_preparation(
        app.clone(),
        "catalog-preparation-cancelled",
        cancelled_enrollment_capability,
        cancelled_response_capability,
        cancelled_preparation.clone(),
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
    assert_eq!(cancelled_status.status(), StatusCode::OK);
    assert_redacted_status(cancelled_status, 4).await?;
    let cancelled_add = device_add(
        &root,
        identity_id,
        cancelled_candidate_device,
        &cancelled_candidate,
        66,
        5,
        head4.hash(),
        5_401,
    );
    let cancelled_add_bytes = cancelled_add.to_deterministic_cbor()?;
    let cancelled_successor = IdentityLogHead::observed(
        identity_id,
        safe(5),
        cancelled_add.entry_hash()?,
    )?;
    let cancelled_provider = provider_body(
        cancelled_challenge.challenge_id(),
        identity_id,
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b3")?,
        safe(2),
        rotated_head_digest,
        &cancelled_preparation,
        &rotated_head,
        head4,
        cancelled_successor,
        cancelled_candidate_device,
        [66; 32],
        &cancelled_add_bytes,
        provider_device,
        &provider,
        authority_device,
        &authority,
        "catalog-provider-cancelled",
        at(5_403),
        at(200_000),
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
    assert_eq!(expired.status(), StatusCode::OK);
    let expired_bytes = assert_redacted_status(expired, 5).await?;
    assert_eq!(expired_bytes, invalidated_bytes);
    let expired_replay = send_preparation(
        app.clone(),
        "catalog-preparation-0001",
        enrollment_capability,
        response_capability,
        preparation,
    )
    .await?;
    assert_eq!(expired_replay.status(), StatusCode::OK);
    assert_catalog_headers(
        &expired_replay,
        RECOVERY_SCOPE_CATALOG_PREPARATION_RECEIPT_CONTENT_TYPE,
    );
    assert_eq!(
        to_bytes(expired_replay.into_body(), 1_100_000).await?,
        preparation_receipt_bytes
    );
    // Replay is an immutable receipt lookup: it survives request expiry,
    // catalog/provider drift, and the H+2 provider-revocation append above.
    let v4_expired_replay = send_history_recovery_request_v4(
        app.clone(),
        request_idempotency,
        enrollment_capability,
        response_capability,
        v4_request,
    )
    .await?;
    assert_eq!(v4_expired_replay.status(), StatusCode::OK);
    assert_catalog_headers(
        &v4_expired_replay,
        HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE,
    );
    assert_eq!(
        to_bytes(v4_expired_replay.into_body(), 16_384).await?,
        v4_receipt
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
