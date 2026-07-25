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
    let shared_catalog = history_testkit::catalog_v2(
        identity_id,
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?,
        1,
        None,
        head3.sequence().get(),
        *head3.hash().as_bytes(),
        authority_device,
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b2")?,
        &authority,
        [31; 32],
        b"opaque-encrypted-catalog-v2",
        2_500,
        250_000,
    );
    assert_eq!(shared_catalog, catalog);
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

    // The reusable testkit driver keeps transport details in this node test
    // while still proving the exact replay bytes at the HTTP boundary.
    let driver_request = history_testkit::HttpRequest::new(
        "PUT",
        RECOVERY_SCOPE_CATALOG_PATH_TEMPLATE
            .replace("{catalog_id}", "0190f2a5-7b1c-7abc-8def-0123456789b1")
            .replace("{generation}", "1"),
        catalog.clone(),
    )
    .header("content-type", RECOVERY_SCOPE_CATALOG_CONTENT_TYPE)
    .header("accept", RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE)
    .header("idempotency-key", "catalog-publish-0001")
    .header("authorization", authorization(&authority_session));
    let driver_responses = history_testkit::run_http_workflow(
        [history_testkit::HttpStep::new("catalog-replay", driver_request)],
        |request| send_history_testkit_request(app.clone(), request),
    )
    .await
    .map_err(|error| format!("{}: {}", error.step, error.source))?;
    assert_eq!(driver_responses[0].status, StatusCode::OK.as_u16());
    assert_eq!(driver_responses[0].body, first_head);
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
    let shared_preparation = history_testkit::preparation_v2(
        challenge.challenge_id(),
        identity_id,
        candidate_device,
        &candidate,
        [55; 32],
        head3.sequence().get(),
        *head3.hash().as_bytes(),
        response_capability,
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?,
        1,
        *catalog_head_digest.as_bytes(),
        "catalog-preparation-0001",
        4_500,
        200_000,
    );
    assert_eq!(shared_preparation, preparation);
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
    let shared_provider_response = history_testkit::ready_provider_response(
        &history_testkit::ProviderResponseInput {
            request: challenge.challenge_id(),
            identity: identity_id,
            catalog_id: uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?,
            generation: 1,
            catalog_head_digest: *catalog_head_digest.as_bytes(),
            preparation: &preparation,
            signed_head: &first_head,
            observed_head_sequence: head3.sequence().get(),
            observed_head_hash: *head3.hash().as_bytes(),
            successor_head_sequence: head4.sequence().get(),
            successor_head_hash: *head4.hash().as_bytes(),
            candidate_device,
            candidate_recipient: [55; 32],
            device_add: &candidate_add_bytes,
            provider_device,
            provider_signer: &provider,
            authority_device,
            authority_signer: &authority,
            response_idempotency_key: "catalog-provider-0001",
            issued_at: 5_300,
            expires_at: 200_000,
        },
    );
    assert_eq!(shared_provider_response, provider_response_body);
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
    let shared_v4_request = history_testkit::request_v4(
        challenge.challenge_id(),
        identity_id,
        candidate_device,
        &candidate,
        [55; 32],
        head3.sequence().get(),
        *head3.hash().as_bytes(),
        head4.sequence().get(),
        *head4.hash().as_bytes(),
        &candidate_add_bytes,
        &preparation,
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?,
        &first_head,
        *catalog_head_digest.as_bytes(),
        response_capability,
        request_idempotency,
        5_300,
        200_000,
    );
    assert_eq!(shared_v4_request, v4_request);

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

    // First admission distinguishes persisted lifecycle terminal states from
    // nonterminal coordinate drift.  Each request uses a fresh idempotency
    // digest but the same approved challenge and artifacts, and every
    // rejected path is asserted before any request row can be written.
    let revoked_capability = [81; 32];
    let revoked_challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([82; 32]),
                identity_id,
                candidate_device,
                public(&candidate),
                DeviceEncryptionPublicKey::try_from([55; 32])?,
                DeviceEnrollmentCapability::new(revoked_capability)?,
            )?,
            at(5_300),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(revoked_challenge) = revoked_challenge else {
        return Err("revoked V4 challenge must be new".into());
    };
    let revoked_cancellation = cancel_enrollment_challenge(
        app.clone(),
        revoked_challenge.challenge_id(),
        revoked_capability,
    )
    .await?;
    assert_eq!(revoked_cancellation.status(), StatusCode::OK);
    let revoked_preparation = preparation_body(
        revoked_challenge.challenge_id(),
        identity_id,
        candidate_device,
        &candidate,
        [55; 32],
        head3,
        response_capability,
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?,
        safe(1),
        catalog_head_digest,
        "catalog-preparation-v4-revoked",
    )?;
    let revoked_request = history_recovery_request_v4_body(
        revoked_challenge.challenge_id(),
        identity_id,
        candidate_device,
        &candidate,
        [55; 32],
        head3,
        head4,
        &candidate_add_bytes,
        &revoked_preparation,
        uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?,
        &first_head,
        catalog_head_digest,
        response_capability,
        "history-recovery-v4-lifecycle-revoked",
    )?;
    assert_error(
        send_history_recovery_request_v4(
            app.clone(),
            "history-recovery-v4-lifecycle-revoked",
            revoked_capability,
            response_capability,
            revoked_request,
        )
        .await?,
        StatusCode::GONE,
        "RECOVERY_PREPARATION_REVOKED",
    )
    .await?;
    assert_history_recovery_request_rows(
        harness.admin_pool(),
        revoked_challenge.challenge_id(),
        0,
    )
    .await?;

    let preparation_snapshot: (i64, Option<i64>) = sqlx::query_as(
        "SELECT expires_at_ms,provider_expires_at_ms
           FROM identity.recovery_scope_catalog_preparations WHERE request_id=$1",
    )
    .bind(*challenge.challenge_id().as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    let catalog_expiry: i64 = sqlx::query_scalar(
        "SELECT expires_at_ms FROM identity.recovery_scope_catalogs
          WHERE identity_id=$1 ORDER BY generation DESC LIMIT 1",
    )
    .bind(identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;

    let expired_request = history_recovery_request_v4_with_outer_tamper(
        &history_recovery_request_v4_with_idempotency(
            &v4_request,
            &candidate,
            "history-recovery-v4-lifecycle-request-expired",
        )?,
        &candidate,
        18,
        at(4_900).to_canonical_value(),
    )?;
    let expired_request = history_recovery_request_v4_with_outer_tamper(
        &expired_request,
        &candidate,
        17,
        at(4_500).to_canonical_value(),
    )?;
    assert_error(
        send_history_recovery_request_v4(
            app.clone(),
            "history-recovery-v4-lifecycle-request-expired",
            enrollment_capability,
            response_capability,
            expired_request,
        )
        .await?,
        StatusCode::GONE,
        "RECOVERY_PREPARATION_EXPIRED",
    )
    .await?;
    assert_history_recovery_request_rows(harness.admin_pool(), challenge.challenge_id(), 0).await?;

    let expired_preparation = history_recovery_request_v4_with_idempotency(
        &v4_request,
        &candidate,
        "history-recovery-v4-lifecycle-preparation-expired",
    )?;
    let mut lifecycle_tx = harness.admin_pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *lifecycle_tx)
        .await?;
    sqlx::query(
        "UPDATE identity.recovery_scope_catalog_preparations
            SET expires_at_ms=$2,provider_expires_at_ms=$2 WHERE request_id=$1",
    )
    .bind(*challenge.challenge_id().as_uuid())
    .bind(6_000_i64)
    .execute(&mut *lifecycle_tx)
    .await?;
    lifecycle_tx.commit().await?;
    clock.set(7_000);
    let persisted_preparation_expires: i64 = sqlx::query_scalar(
        "SELECT expires_at_ms FROM identity.recovery_scope_catalog_preparations
          WHERE request_id=$1",
    )
    .bind(*challenge.challenge_id().as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(200_000 > 7_000, "signed request remains valid at trusted_now");
    assert!(
        persisted_preparation_expires <= 7_000,
        "persisted preparation is expired at trusted_now"
    );
    assert_error(
        send_history_recovery_request_v4(
            app.clone(),
            "history-recovery-v4-lifecycle-preparation-expired",
            enrollment_capability,
            response_capability,
            expired_preparation,
        )
        .await?,
        StatusCode::GONE,
        "RECOVERY_PREPARATION_EXPIRED",
    )
    .await?;
    assert_history_recovery_request_rows(harness.admin_pool(), challenge.challenge_id(), 0).await?;
    let mut lifecycle_tx = harness.admin_pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *lifecycle_tx)
        .await?;
    sqlx::query(
        "UPDATE identity.recovery_scope_catalog_preparations
            SET expires_at_ms=$2,provider_expires_at_ms=$3 WHERE request_id=$1",
    )
    .bind(*challenge.challenge_id().as_uuid())
    .bind(preparation_snapshot.0)
    .bind(preparation_snapshot.1)
    .execute(&mut *lifecycle_tx)
    .await?;
    clock.set(5_300);
    lifecycle_tx.commit().await?;

    let expired_provider = history_recovery_request_v4_with_idempotency(
        &v4_request,
        &candidate,
        "history-recovery-v4-lifecycle-provider-expired",
    )?;
    let mut lifecycle_tx = harness.admin_pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *lifecycle_tx)
        .await?;
    sqlx::query(
        "UPDATE identity.recovery_scope_catalog_preparations
            SET provider_expires_at_ms=$2 WHERE request_id=$1",
    )
    .bind(*challenge.challenge_id().as_uuid())
    .bind(6_000_i64)
    .execute(&mut *lifecycle_tx)
    .await?;
    lifecycle_tx.commit().await?;
    clock.set(7_000);
    assert_error(
        send_history_recovery_request_v4(
            app.clone(),
            "history-recovery-v4-lifecycle-provider-expired",
            enrollment_capability,
            response_capability,
            expired_provider,
        )
        .await?,
        StatusCode::GONE,
        "RECOVERY_PREPARATION_EXPIRED",
    )
    .await?;
    assert_history_recovery_request_rows(harness.admin_pool(), challenge.challenge_id(), 0).await?;
    clock.set(5_300);
    let mut lifecycle_tx = harness.admin_pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *lifecycle_tx)
        .await?;
    sqlx::query(
        "UPDATE identity.recovery_scope_catalog_preparations
            SET provider_expires_at_ms=$2 WHERE request_id=$1",
    )
    .bind(*challenge.challenge_id().as_uuid())
    .bind(preparation_snapshot.1)
    .execute(&mut *lifecycle_tx)
    .await?;
    lifecycle_tx.commit().await?;

    let expired_catalog = history_recovery_request_v4_with_idempotency(
        &v4_request,
        &candidate,
        "history-recovery-v4-lifecycle-catalog-expired",
    )?;
    let mut lifecycle_tx = harness.admin_pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *lifecycle_tx)
        .await?;
    sqlx::query(
        "UPDATE identity.recovery_scope_catalogs SET expires_at_ms=$2
          WHERE identity_id=$1 AND generation=1",
    )
    .bind(identity_id.to_string())
    .bind(6_000_i64)
    .execute(&mut *lifecycle_tx)
    .await?;
    lifecycle_tx.commit().await?;
    clock.set(7_000);
    assert_error(
        send_history_recovery_request_v4(
            app.clone(),
            "history-recovery-v4-lifecycle-catalog-expired",
            enrollment_capability,
            response_capability,
            expired_catalog,
        )
        .await?,
        StatusCode::GONE,
        "RECOVERY_CATALOG_EXPIRED",
    )
    .await?;
    assert_history_recovery_request_rows(harness.admin_pool(), challenge.challenge_id(), 0).await?;
    clock.set(5_300);
    let mut lifecycle_tx = harness.admin_pool().begin().await?;
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *lifecycle_tx)
        .await?;
    sqlx::query(
        "UPDATE identity.recovery_scope_catalogs SET expires_at_ms=$2
          WHERE identity_id=$1 AND generation=1",
    )
    .bind(identity_id.to_string())
    .bind(catalog_expiry)
    .execute(&mut *lifecycle_tx)
    .await?;
    lifecycle_tx.commit().await?;

    let drift_request = history_recovery_request_v4_with_idempotency(
        &v4_request,
        &candidate,
        "history-recovery-v4-lifecycle-catalog-drift",
    )?;
    sqlx::query(
        "UPDATE identity.recovery_scope_catalogs SET head_digest=$2
          WHERE identity_id=$1 AND generation=1",
    )
    .bind(identity_id.to_string())
    .bind([99_u8; 32].as_slice())
    .execute(harness.admin_pool())
    .await?;
    assert_error(
        send_history_recovery_request_v4(
            app.clone(),
            "history-recovery-v4-lifecycle-catalog-drift",
            enrollment_capability,
            response_capability,
            drift_request,
        )
        .await?,
        StatusCode::PRECONDITION_FAILED,
        "CATALOG_HEAD_CHANGED",
    )
    .await?;
    assert_history_recovery_request_rows(harness.admin_pool(), challenge.challenge_id(), 0).await?;
    sqlx::query(
        "UPDATE identity.recovery_scope_catalogs SET head_digest=$2
          WHERE identity_id=$1 AND generation=1",
    )
    .bind(identity_id.to_string())
    .bind(catalog_head_digest.as_bytes().as_slice())
    .execute(harness.admin_pool())
    .await?;

    sqlx::query("REVOKE SELECT ON identity.recovery_scope_catalogs FROM dtx_identity_runtime")
        .execute(harness.admin_pool())
        .await?;
    let unavailable_request = history_recovery_request_v4_with_idempotency(
        &v4_request,
        &candidate,
        "history-recovery-v4-lifecycle-unavailable",
    )?;
    assert_error(
        send_history_recovery_request_v4(
            app.clone(),
            "history-recovery-v4-lifecycle-unavailable",
            enrollment_capability,
            response_capability,
            unavailable_request,
        )
        .await?,
        StatusCode::SERVICE_UNAVAILABLE,
        "IDENTITY_SERVICE_UNAVAILABLE",
    )
    .await?;
    assert_history_recovery_request_rows(harness.admin_pool(), challenge.challenge_id(), 0).await?;
    sqlx::query("GRANT SELECT ON identity.recovery_scope_catalogs TO dtx_identity_runtime")
        .execute(harness.admin_pool())
        .await?;

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

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn completion_http_fixture_accepts_exact_post_replay_and_readback() -> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let clock = Arc::new(TestClock::new(5_000));
    let root = key(101);
    let candidate = key(102);
    let identity_repository = IdentityLogRepository::new();
    let genesis_event = super::genesis(&root, &key(103));
    let identity = genesis_event.identity_id();
    let head1 = committed(identity_repository.append(&store, &super::append_command(1, None, &genesis_event)?, at(1_001)).await?)?;
    let candidate_device = DeviceId::from_str("0190f2a5-7b1c-7abc-8def-0123456789c1")?;
    let candidate_add = super::device_add(&root, identity, candidate_device, &candidate, 102, 2, head1.hash(), 1_010);
    let head2 = committed(identity_repository.append(&store, &super::append_command(2, Some(head1), &candidate_add)?, at(1_011)).await?)?;
    let candidate_session = super::session(&store, identity, candidate_device, &candidate, 201, at(2_000)).await?;

    let catalog_id = Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789d1")?;
    let cert_issuer = SigningKey::from_bytes(&[106;32]);
    let leaf = history_testkit::catalog_leaf_v2(catalog_id, 1, 1, [1;32], [2;32], cert_issuer.verifying_key().to_bytes(), 2_000, 8_000, [3;32]);
    let leaf_digest = Sha256Digest::hash_domain(b"dirextalk.recovery-scope-catalog-leaf-commitment.v2\0", &leaf);
    let leaf_set_digest = Sha256Digest::hash_domain(b"dirextalk.history-recovery.leaf-set.v2\0", &encode_deterministic_cbor(&CanonicalValue::Array(vec![CanonicalValue::Bytes(leaf_digest.as_bytes().to_vec())]))?);
    let catalog_upload = history_testkit::catalog_v2_with_leaf_set(identity, catalog_id, 1, None, head1.sequence().get(), *head1.hash().as_bytes(), candidate_device, Uuid::now_v7(), &root, *leaf_digest.as_bytes(), *leaf_set_digest.as_bytes(), b"opaque-catalog", 2_500, 250_000);
    let CanonicalValue::Map(upload_fields) = decode_deterministic_cbor(&catalog_upload)? else { unreachable!() };
    let catalog_head = encode_deterministic_cbor(&upload_fields[0].1)?;
    let catalog_head_digest = Sha256Digest::hash_domain(b"dirextalk.recovery-scope-catalog-head.v2\0", &catalog_head);
    let request_id = DeviceEnrollmentChallengeId::new();
    let preparation = history_testkit::preparation_v2(request_id, identity, candidate_device, &candidate, [51; 32], head1.sequence().get(), *head1.hash().as_bytes(), [52; 32], catalog_id, 1, *catalog_head_digest.as_bytes(), "completion-prep", 2_500, 250_000);
    let request = history_testkit::request_v4_with_leaf_digest(request_id, identity, candidate_device, &candidate, [51; 32], head1.sequence().get(), *head1.hash().as_bytes(), head2.sequence().get(), *head2.hash().as_bytes(), &candidate_add.to_deterministic_cbor()?, &preparation, catalog_id, &catalog_head, *catalog_head_digest.as_bytes(), *leaf_digest.as_bytes(), [52; 32], "completion-request", 2_500, 250_000);
    let request_value = decode_deterministic_cbor(&request)?;
    let CanonicalValue::Map(request_fields) = request_value else { unreachable!() };
    let manifest = encode_deterministic_cbor(&request_fields[14].1)?;
    let CanonicalValue::Map(manifest_fields) = &request_fields[14].1 else { unreachable!() };
    assert_eq!(manifest_fields[8].1, CanonicalValue::Bytes(leaf_set_digest.as_bytes().to_vec()));
    let request_digest = Sha256Digest::hash_domain(b"dirextalk.history-recovery.request.v4\0", &request);
    let manifest_digest = Sha256Digest::hash_domain(b"dirextalk.history-recovery.manifest.v2\0", &manifest);
    let device_add_digest = Sha256Digest::hash_domain(history_testkit::IDENTITY_DEVICE_ADD_DOMAIN, &candidate_add.to_deterministic_cbor()?);
    let request_id_uuid: Uuid = request_id.into();
    let request_challenge_id = request_id;
    let request_id = request_id_uuid;
    let request_value = sqlx::query("INSERT INTO identity.history_recovery_requests(request_id,identity_id,candidate_device_id,candidate_signing_key,candidate_recipient_key,pre_head_sequence,pre_head_hash,post_head_sequence,post_head_hash,device_add_bytes,device_add_digest,preparation_bytes,preparation_digest,manifest_bytes,manifest_digest,issued_at_ms,expires_at_ms,response_capability_digest,idempotency_digest,candidate_signature,request_bytes,request_digest,receipt_bytes,accepted_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)")
        .bind(request_id).bind(identity.to_string()).bind(*candidate_device.as_uuid()).bind(candidate.verifying_key().to_bytes().to_vec()).bind(vec![51_u8;32]).bind(head1.sequence().get() as i64).bind(head1.hash().as_bytes().to_vec()).bind(head2.sequence().get() as i64).bind(head2.hash().as_bytes().to_vec()).bind(candidate_add.to_deterministic_cbor()?).bind(device_add_digest.as_bytes().to_vec()).bind(&preparation).bind(Sha256Digest::hash_domain(history_testkit::PREPARATION_DIGEST_DOMAIN,&preparation).as_bytes().to_vec()).bind(&manifest).bind(manifest_digest.as_bytes().to_vec()).bind(2_500_i64).bind(250_000_i64).bind(vec![52_u8;32]).bind(vec![54_u8;32]).bind(vec![0_u8;64]).bind(&request).bind(request_digest.as_bytes().to_vec()).bind(vec![1_u8]).bind(2_500_i64).execute(harness.identity_runtime_pool()).await?;
    assert_eq!(request_value.rows_affected(), 1);

    let offer = history_testkit::offer_v3(request_challenge_id, *request_digest.as_bytes(), *manifest_digest.as_bytes(), catalog_id, 1, *catalog_head_digest.as_bytes(), *leaf_set_digest.as_bytes(), [32;32], *Sha256Digest::hash_domain(b"dirextalk.recovery-recipient-key.v1\0", &[51;32]).as_bytes(), b"opaque-offer", [61;32], 2_500, 250_000);
    let mailbox_id = Uuid::now_v7();
    let envelope_id = Uuid::now_v7();
    let delivery_fact_id = Uuid::now_v7();
    let provider = key(104);
    let authority = key(105);
    let provider_descriptor = CanonicalValue::Map(vec![field(1, CanonicalValue::Unsigned(2)), field(2, CanonicalValue::Text(Uuid::now_v7().to_string())), field(3, public(&provider).to_canonical_value())]);
    let authority_descriptor = CanonicalValue::Map(vec![field(1, CanonicalValue::Unsigned(1)), field(2, CanonicalValue::Text(Uuid::now_v7().to_string())), field(3, public(&authority).to_canonical_value())]);
    let grant = history_testkit::grant_v5(identity, request_challenge_id, *request_digest.as_bytes(), *manifest_digest.as_bytes(), catalog_id, 1, &catalog_head, *catalog_head_digest.as_bytes(), *leaf_digest.as_bytes(), 1, *leaf_set_digest.as_bytes(), candidate_device, &candidate, [51;32], head1.sequence().get(), *head1.hash().as_bytes(), head2.sequence().get(), *head2.hash().as_bytes(), *device_add_digest.as_bytes(), *Sha256Digest::hash_domain(history_testkit::PREPARATION_DIGEST_DOMAIN,&preparation).as_bytes(), provider_descriptor, authority_descriptor.clone(), mailbox_id, envelope_id, 0, delivery_fact_id, 2_500, 250_000, &provider, &authority, &offer, [54;32], 2_500, 250_000);
    let grant_digest = Sha256Digest::hash_domain(b"dirextalk.history-recovery.grant.v5\0", &grant);
    let offer_digest = Sha256Digest::hash_domain(b"dirextalk.history-recovery.recipient-offer.v3\0", &offer);
    let delivery = history_testkit::delivery_v2(delivery_fact_id, mailbox_id, envelope_id, 1, *grant_digest.as_bytes(), *offer_digest.as_bytes(), request_id, *candidate_device.as_uuid(), 3_000, Uuid::now_v7(), Uuid::now_v7());
    let delivery_digest = Sha256Digest::hash_domain(b"dirextalk.history-recovery.delivery-fact.v2\0", &delivery);
    let context = history_testkit::completion_context_v2([71;32], Uuid::now_v7(), request_id, *request_digest.as_bytes(), identity, *candidate_device.as_uuid(), catalog_id, 1, *catalog_head_digest.as_bytes(), 1, *leaf_set_digest.as_bytes());
    let completion_id = match decode_deterministic_cbor(&context)? { CanonicalValue::Map(fields) => match &fields[2].1 { CanonicalValue::Text(value) => Uuid::parse_str(value)?, _ => unreachable!() }, _ => unreachable!() };
    let child = SigningKey::from_bytes(&[107;32]);
    let context_digest = Sha256Digest::hash_domain(b"dirextalk.history-recovery-completion-context.v2\0", &context);
    let certificate = history_testkit::child_certificate_v1(&cert_issuer, &child, *context_digest.as_bytes(), [3;32], 1, *catalog_head_digest.as_bytes(), 1, 1, *leaf_digest.as_bytes(), 3_000, 8_000);
    let evidence = history_testkit::evidence_v1(&certificate, &child, *context_digest.as_bytes(), 1, *catalog_head_digest.as_bytes(), 1, 1, *leaf_digest.as_bytes(), 3_000, 8_000);
    let pre_entry = history_testkit::entry_v2(1, &leaf, &[], &certificate, &evidence);
    let proof = history_testkit::proof_v2(completion_id, 1, 1, &pre_entry, &[]);
    let entry = history_testkit::entry_v2(1, &leaf, &proof, &certificate, &evidence);
    dtx_history_recovery_protocol::validate_completion_entry_v2(
        &entry,
        dtx_history_recovery_protocol::CompletionEntryExpectations {
            catalog_id,
            generation: 1,
            index: 1,
            completion_id,
            count: 1,
            leaf_digest,
            context_digest,
            head_digest: catalog_head_digest,
            request_issued_at: 2_500,
            request_expires_at: 250_000,
            head_issued_at: 2_500,
            head_expires_at: 250_000,
            grant_issued_at: 2_500,
            grant_expires_at: 250_000,
        },
    )
    .expect("entry");
    let signer = SigningKey::from_bytes(&[108;32]);
    let completion_idempotency = Sha256Digest::hash_domain(b"dirextalk.history-recovery.completion-idempotency.v2\0", b"completion-00001");
    let input = history_testkit::CompletionV2Input { completion_id, identity, candidate_device: *candidate_device.as_uuid(), highwater: head1.sequence().get(), head_at_highwater: *head1.hash().as_bytes(), highwater_next: head2.sequence().get(), final_head_hash: *head2.hash().as_bytes(), catalog_id, catalog_generation: 1, catalog_head: catalog_head.clone(), catalog_head_digest: *catalog_head_digest.as_bytes(), catalog_root_digest: *leaf_digest.as_bytes(), leaf_set_digest: *leaf_set_digest.as_bytes(), preparation: preparation.clone(), request, request_digest: *request_digest.as_bytes(), manifest, manifest_digest: *manifest_digest.as_bytes(), grant, grant_digest: *grant_digest.as_bytes(), offer: offer.clone(), offer_digest: *offer_digest.as_bytes(), delivery, delivery_digest: *delivery_digest.as_bytes(), entries: vec![entry], issued_at: 3_000, expires_at: 8_000, idempotency_digest: *completion_idempotency.as_bytes(), context };
    let command = history_testkit::completion_command_v2(&input, &candidate);
    dtx_history_recovery_protocol::validate_catalog_head_v2(&input.catalog_head).expect("head");
    dtx_history_recovery_protocol::validate_request_v4(&input.request).expect("request");
    dtx_history_recovery_protocol::validate_offer_v3(&input.offer).expect("offer");
    dtx_history_recovery_protocol::validate_grant_v5(&input.grant).expect("grant");
    dtx_history_recovery_protocol::validate_delivery_v2(&input.delivery).expect("delivery");
    let _parsed = dtx_identity_persistence::HistoryRecoveryCompletionCommand::parse(
        command.clone(),
        completion_idempotency,
    )
    .expect("completion fixture parses");
    let config = CompletionSignerConfig { key_id: Uuid::now_v7(), epoch: 1, rollback_floor_epoch: 1, issued_at: at(2_000), expires_at: at(9_000), previous_descriptor_digest: None, signing_key: signer };
    let descriptor1 = dtx_identity_persistence::CompletionKeyDescriptor::from_signer(
        dtx_identity_persistence::CompletionSignerMetadata {
            key_id: config.key_id,
            epoch: config.epoch,
            rollback_floor_epoch: config.rollback_floor_epoch,
            issued_at: config.issued_at,
            expires_at: config.expires_at,
            previous_descriptor_digest: config.previous_descriptor_digest,
        },
        AUDIENCE,
        &config.signing_key,
    )?;
    let app = identity_bootstrap_router_with_state(IdentityBootstrapState::with_clock_and_device_session_audience(store.clone(), clock.clone(), AUDIENCE).with_completion_signer_config(config.clone())?);
    let invalid = app.clone().oneshot(Request::builder().method("POST").uri(HISTORY_RECOVERY_COMPLETION_PATH.replace("{completion_id}", &completion_id.to_string())).header(header::CONTENT_TYPE, HISTORY_RECOVERY_COMPLETION_CONTENT_TYPE).header("idempotency-key", "completion-invalid").header(header::AUTHORIZATION, super::authorization(&candidate_session)).body(Body::from(vec![0_u8]))?).await?;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(dtx_identity_persistence::HistoryRecoveryCompletionRepository.current_descriptor(&store).await?.is_none());
    let invalid_provider = CanonicalValue::Map(vec![field(1, CanonicalValue::Unsigned(2)), field(2, CanonicalValue::Text(candidate_device.to_string())), field(3, public(&provider).to_canonical_value())]);
    let invalid_grant = history_testkit::grant_v5(identity, request_challenge_id, *request_digest.as_bytes(), *manifest_digest.as_bytes(), catalog_id, 1, &catalog_head, *catalog_head_digest.as_bytes(), *leaf_digest.as_bytes(), 1, *leaf_set_digest.as_bytes(), candidate_device, &candidate, [51;32], head1.sequence().get(), *head1.hash().as_bytes(), head2.sequence().get(), *head2.hash().as_bytes(), *device_add_digest.as_bytes(), *Sha256Digest::hash_domain(history_testkit::PREPARATION_DIGEST_DOMAIN,&preparation).as_bytes(), invalid_provider, authority_descriptor.clone(), mailbox_id, envelope_id, 0, delivery_fact_id, 2_500, 250_000, &provider, &authority, &offer, [54;32], 2_500, 250_000);
    let invalid_grant_digest = Sha256Digest::hash_domain(b"dirextalk.history-recovery.grant.v5\0", &invalid_grant);
    let invalid_delivery = history_testkit::delivery_v2(delivery_fact_id, mailbox_id, envelope_id, 1, *invalid_grant_digest.as_bytes(), *offer_digest.as_bytes(), request_id, *candidate_device.as_uuid(), 3_000, Uuid::now_v7(), Uuid::now_v7());
    let invalid_delivery_digest = Sha256Digest::hash_domain(b"dirextalk.history-recovery.delivery-fact.v2\0", &invalid_delivery);
    let mut invalid_input = input.clone();
    invalid_input.grant = invalid_grant;
    invalid_input.grant_digest = *invalid_grant_digest.as_bytes();
    invalid_input.delivery = invalid_delivery;
    invalid_input.delivery_digest = *invalid_delivery_digest.as_bytes();
    invalid_input.idempotency_digest = *Sha256Digest::hash_domain(b"dirextalk.history-recovery.completion-idempotency.v2\0", b"completion-invalid-grant").as_bytes();
    let invalid_command = history_testkit::completion_command_v2(&invalid_input, &candidate);
    let invalid = app.clone().oneshot(Request::builder().method("POST").uri(HISTORY_RECOVERY_COMPLETION_PATH.replace("{completion_id}", &completion_id.to_string())).header(header::CONTENT_TYPE, HISTORY_RECOVERY_COMPLETION_CONTENT_TYPE).header("idempotency-key", "completion-invalid-grant").header(header::AUTHORIZATION, super::authorization(&candidate_session)).body(Body::from(invalid_command))?).await?;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(dtx_identity_persistence::HistoryRecoveryCompletionRepository.current_descriptor(&store).await?.is_none());
    let completion_count: i64 = sqlx::query_scalar("SELECT count(*) FROM identity.history_recovery_completions_v2 WHERE identity_id=$1").bind(identity.to_string()).fetch_one(harness.identity_runtime_pool()).await?;
    assert_eq!(completion_count, 0);
    let current_descriptor = app.clone().oneshot(Request::builder().method("GET").uri(HISTORY_RECOVERY_COMPLETION_KEY_PATH).body(Body::empty())?).await?;
    assert_eq!(current_descriptor.status(), StatusCode::OK);
    assert_eq!(to_bytes(current_descriptor.into_body(), 16_384).await?.as_ref(), descriptor1.exact_bytes.as_slice());
    let descriptor1_hex = descriptor1.digest.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let historical_path = HISTORY_RECOVERY_COMPLETION_KEY_HISTORICAL_PATH.replace("{descriptor_digest}", &descriptor1_hex);
    let uri = HISTORY_RECOVERY_COMPLETION_PATH.replace("{completion_id}", &completion_id.to_string());
    let first = Request::builder().method("POST").uri(&uri).header(header::CONTENT_TYPE, HISTORY_RECOVERY_COMPLETION_CONTENT_TYPE).header("idempotency-key", "completion-00001").header(header::AUTHORIZATION, super::authorization(&candidate_session)).body(Body::from(command.clone()))?;
    let second = Request::builder().method("POST").uri(&uri).header(header::CONTENT_TYPE, HISTORY_RECOVERY_COMPLETION_CONTENT_TYPE).header("idempotency-key", "completion-00001").header(header::AUTHORIZATION, super::authorization(&candidate_session)).body(Body::from(command.clone()))?;
    let (first, second) = tokio::join!(app.clone().oneshot(first), app.clone().oneshot(second));
    let first = first?;
    let second = second?;
    assert!(
        (first.status() == StatusCode::CREATED && second.status() == StatusCode::OK)
            || (first.status() == StatusCode::OK && second.status() == StatusCode::CREATED)
    );
    let first_receipt = to_bytes(first.into_body(), 16_384).await?.to_vec();
    let second_receipt = to_bytes(second.into_body(), 16_384).await?.to_vec();
    assert_eq!(first_receipt, second_receipt);
    let receipt = first_receipt;
    let mut divergent_input = input.clone();
    divergent_input.idempotency_digest = *Sha256Digest::hash_domain(
        b"dirextalk.history-recovery.completion-idempotency.v2\0",
        b"completion-00002",
    )
    .as_bytes();
    let divergent = history_testkit::completion_command_v2(&divergent_input, &candidate);
    let divergent = app.clone().oneshot(Request::builder().method("POST").uri(&uri).header(header::CONTENT_TYPE, HISTORY_RECOVERY_COMPLETION_CONTENT_TYPE).header("idempotency-key", "completion-00002").header(header::AUTHORIZATION, super::authorization(&candidate_session)).body(Body::from(divergent))?).await?;
    assert_eq!(divergent.status(), StatusCode::CONFLICT);
    let readback = app.oneshot(Request::builder().method("GET").uri(&uri).header(header::AUTHORIZATION, super::authorization(&candidate_session)).body(Body::empty())?).await?;
    assert_eq!(readback.status(), StatusCode::OK);
    assert_eq!(to_bytes(readback.into_body(), 16_384).await?.as_ref(), receipt.as_slice());
    let signer2 = SigningKey::from_bytes(&[109;32]);
    let config2 = CompletionSignerConfig { key_id: Uuid::now_v7(), epoch: 2, rollback_floor_epoch: 2, issued_at: at(6_000), expires_at: at(10_000), previous_descriptor_digest: Some(descriptor1.digest), signing_key: signer2 };
    let descriptor2 = dtx_identity_persistence::HistoryRecoveryCompletionRepository
        .ensure_descriptor(
            &store,
            AUDIENCE,
            dtx_identity_persistence::CompletionSignerMetadata {
                key_id: config2.key_id,
                epoch: config2.epoch,
                rollback_floor_epoch: config2.rollback_floor_epoch,
                issued_at: config2.issued_at,
                expires_at: config2.expires_at,
                previous_descriptor_digest: config2.previous_descriptor_digest,
            },
            &config2.signing_key,
            at(6_000),
        )
        .await?;
    assert_ne!(descriptor1.digest, descriptor2.digest);
    let before_rejected = dtx_identity_persistence::HistoryRecoveryCompletionRepository.current_descriptor(&store).await?.expect("descriptor head").digest;
    let rejected_previous = dtx_identity_persistence::HistoryRecoveryCompletionRepository
        .ensure_descriptor(&store, AUDIENCE, dtx_identity_persistence::CompletionSignerMetadata { key_id: Uuid::now_v7(), epoch: 3, rollback_floor_epoch: 1, issued_at: at(6_000), expires_at: at(10_000), previous_descriptor_digest: Some(Sha256Digest::from_bytes([250;32])) }, &SigningKey::from_bytes(&[110;32]), at(6_000))
        .await;
    assert!(rejected_previous.is_err());
    assert_eq!(dtx_identity_persistence::HistoryRecoveryCompletionRepository.current_descriptor(&store).await?.expect("descriptor head").digest, before_rejected);
    let rejected_epoch = dtx_identity_persistence::HistoryRecoveryCompletionRepository
        .ensure_descriptor(&store, AUDIENCE, dtx_identity_persistence::CompletionSignerMetadata { key_id: Uuid::now_v7(), epoch: 4, rollback_floor_epoch: 2, issued_at: at(6_000), expires_at: at(10_000), previous_descriptor_digest: Some(descriptor2.digest) }, &SigningKey::from_bytes(&[111;32]), at(6_000))
        .await;
    assert!(rejected_epoch.is_err());
    let rejected_floor = dtx_identity_persistence::HistoryRecoveryCompletionRepository
        .ensure_descriptor(&store, AUDIENCE, dtx_identity_persistence::CompletionSignerMetadata { key_id: Uuid::now_v7(), epoch: 3, rollback_floor_epoch: 1, issued_at: at(6_000), expires_at: at(10_000), previous_descriptor_digest: Some(descriptor2.digest) }, &SigningKey::from_bytes(&[112;32]), at(6_000))
        .await;
    assert!(rejected_floor.is_err());
    assert_eq!(dtx_identity_persistence::HistoryRecoveryCompletionRepository.current_descriptor(&store).await?.expect("descriptor head").digest, before_rejected);
    let restarted = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let app2 = identity_bootstrap_router_with_state(IdentityBootstrapState::with_clock_and_device_session_audience(restarted, clock, AUDIENCE).with_completion_signer_config(config2)?);
    let current2 = app2.clone().oneshot(Request::builder().method("GET").uri(HISTORY_RECOVERY_COMPLETION_KEY_PATH).body(Body::empty())?).await?;
    assert_eq!(current2.status(), StatusCode::OK);
    assert_eq!(to_bytes(current2.into_body(), 16_384).await?.as_ref(), descriptor2.exact_bytes.as_slice());
    let historical2 = app2.oneshot(Request::builder().method("GET").uri(&historical_path).body(Body::empty())?).await?;
    assert_eq!(historical2.status(), StatusCode::OK);
    assert_eq!(to_bytes(historical2.into_body(), 16_384).await?.as_ref(), descriptor1.exact_bytes.as_slice());
    Ok(())
}
