#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the two-database acceptance keeps the complete externally observable V5 recovery workflow together"
)]
async fn federated_v5_recovery_and_removal_use_only_fresh_origin_identity_facts()
-> Result<(), Box<dyn Error>> {
    let origin_harness = support::PostgresHarness::start().await?;
    let group_harness = support::PostgresHarness::start().await?;
    let origin_store =
        IdentityPgStore::connect(origin_harness.identity_runtime_options(), 8).await?;
    let group_identity_store =
        IdentityPgStore::connect(group_harness.identity_runtime_options(), 4).await?;
    let group_store = GroupPgStore::connect(group_harness.group_runtime_options(), 4).await?;

    let origin_controller = enroll_active_device(&origin_store, 151, 152, 153, [154; 32]).await?;
    replicate_initial_identity(&group_identity_store, &origin_controller, 152, NOW).await?;
    let group_controller = issue_same_identity_device_session(
        &group_identity_store,
        &origin_controller,
        SigningKey::from_bytes(&origin_controller.device.to_bytes()),
        origin_controller.device_id,
        [155; 32],
        "federated-v5-group-controller",
        156,
    )
    .await?;
    let identity_app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            origin_store.clone(),
            Arc::new(FixedClock(NOW)),
            AUDIENCE,
        ),
    );
    let (identity_origin, identity_server) =
        start_identity_server_at(origin_store.clone(), NOW).await?;
    let tenant_id = TenantId::new();
    let group_app = group_router_with_state(
        GroupNodeState::with_clock(group_store, tenant_id, Arc::new(FixedClock(NOW)))
            .with_mls_sequencer_signing_key(SigningKey::from_bytes(&[157; 32]))
            .with_public_origin_and_allowed_http_identity_origins(
                AUDIENCE,
                [identity_origin.clone()],
            )?,
    );
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let create_key = "federated-v5-create-0001";
    let create = send_mutation(
        group_app.clone(),
        "PUT",
        &scope_path,
        GROUP_CREATE_CONTENT_TYPE,
        create_key,
        &group_controller,
        create_body(&group_controller, scope, &scope_path, create_key, 1_000)?,
    )
    .await?;
    assert_eq!(create.status(), StatusCode::CREATED);

    let bootstrap_submission = RequestId::new();
    let bootstrap_path = format!("{scope_path}/mls-commits/{bootstrap_submission}");
    let bootstrap_key = "federated-v5-bootstrap-0001";
    let bootstrap = send_mutation(
        group_app.clone(),
        "POST",
        &bootstrap_path,
        MLS_COMMIT_CONTENT_TYPE,
        bootstrap_key,
        &group_controller,
        mls_commit_body(
            &group_controller,
            &group_controller,
            scope,
            bootstrap_submission,
            bootstrap_key,
            0,
            Sha256Digest::from_bytes([0; 32]),
            vec![0xd1; 48],
            MlsCommitAuthorization::OwnerBootstrap,
        )?,
    )
    .await?;
    assert_eq!(bootstrap.status(), StatusCode::CREATED);
    let bootstrap_receipt = response_bytes(bootstrap).await?;
    let (bootstrap_receipt_digest, bootstrap_head) = mls_receipt_facts(&bootstrap_receipt)?;
    let bootstrap_confirmation = group_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "{bootstrap_path}/confirmations/{}",
                    group_controller.device_id
                ))
                .header(header::CONTENT_TYPE, MLS_CONFIRMATION_CONTENT_TYPE)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(
                        group_controller.session_id,
                        group_controller.session_secret,
                    ),
                )
                .body(Body::from(mls_confirmation_body(
                    &group_controller,
                    bootstrap_submission,
                    bootstrap_receipt_digest,
                    bootstrap_head,
                )?))?,
        )
        .await?;
    assert_eq!(bootstrap_confirmation.status(), StatusCode::NO_CONTENT);

    let stale_recovery = prepare_scoped_history_recovery(
        identity_app.clone(),
        &origin_store,
        &origin_controller,
        scope,
        158,
        159,
        [160; 32],
        [161; 32],
        "federated-v5-history-recovery",
        NOW - 200,
    )
    .await?;
    let recovery = prepare_scoped_history_recovery(
        identity_app.clone(),
        &origin_store,
        &origin_controller,
        scope,
        162,
        163,
        [164; 32],
        [165; 32],
        "federated-v5-current-history-recovery",
        NOW - 100,
    )
    .await?;
    let current_origin_head = IdentityLogRepository::new()
        .load(&origin_store, origin_controller.identity_id)
        .await?
        .ok_or("origin identity missing after recovery approval")?
        .head();
    assert_ne!(stale_recovery.approved_head, current_origin_head);
    assert_eq!(recovery.approved_head, current_origin_head);
    let stale_package_digest = publish_scoped_recovery_key_package(
        identity_app.clone(),
        &origin_controller,
        &stale_recovery,
        scope,
        current_origin_head,
        vec![0xd0; 64],
        "federated-v5-stale-package-0001",
    )
    .await?;
    let package_digest = publish_scoped_recovery_key_package(
        identity_app.clone(),
        &origin_controller,
        &recovery,
        scope,
        current_origin_head,
        vec![0xd2; 64],
        "federated-v5-package-0001",
    )
    .await?;
    seed_recovery_authorization_artifacts(
        origin_harness.admin_pool(),
        &origin_controller,
        &stale_recovery,
        stale_package_digest,
    )
    .await?;
    seed_recovery_authorization_artifacts(
        origin_harness.admin_pool(),
        &origin_controller,
        &recovery,
        package_digest,
    )
    .await?;
    let stale_group_identity = IdentityLogRepository::new()
        .load(&group_identity_store, origin_controller.identity_id)
        .await?
        .ok_or("group-side controller identity missing")?;
    assert_eq!(
        stale_group_identity
            .projection()
            .device_status(recovery.device.device_id),
        None,
        "the group database must not receive the recovered identity leaf"
    );

    let authorization_query = MlsV5RecoveryAuthorizationQuery::new(
        origin_controller.identity_id,
        recovery.request_id,
        recovery.device.device_id,
        origin_controller.device_id,
        current_origin_head.hash(),
        package_digest,
        recovery.request_digest,
        recovery.scope_digest,
    );
    let authorization_path = format!(
        "{}?{}",
        MLS_V5_RECOVERY_AUTHORIZATION_PATH_TEMPLATE
            .replace("{identity_id}", &origin_controller.identity_id.to_string())
            .replace("{request_id}", &recovery.request_id.to_string()),
        authorization_query.canonical_query(),
    );
    let wrong_media = identity_app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&authorization_path)
                .header(header::ACCEPT, "application/octet-stream")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(wrong_media.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let invented_proof = identity_app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&authorization_path)
                .header(header::ACCEPT, MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE)
                .header(header::AUTHORIZATION, "Bearer invented-portable-proof")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(invented_proof.status(), StatusCode::UNPROCESSABLE_ENTITY);
    sqlx::query(
        "UPDATE messaging.history_recovery_offers
            SET expires_at_ms=$3
          WHERE identity_id=$1 AND request_id=$2",
    )
    .bind(origin_controller.identity_id.to_string())
    .bind(*recovery.request_id.as_uuid())
    .bind(NOW)
    .execute(origin_harness.admin_pool())
    .await?;
    let expired = identity_app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&authorization_path)
                .header(header::ACCEPT, MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(expired.status(), StatusCode::NOT_FOUND);
    sqlx::query(
        "UPDATE messaging.history_recovery_offers
            SET expires_at_ms=$3
          WHERE identity_id=$1 AND request_id=$2",
    )
    .bind(origin_controller.identity_id.to_string())
    .bind(*recovery.request_id.as_uuid())
    .bind(NOW + 60_000)
    .execute(origin_harness.admin_pool())
    .await?;

    let stale_submission = RequestId::new();
    let stale_path = format!("{scope_path}/mls-commits/{stale_submission}");
    let stale_key = "federated-v5-stale-head-0001";
    let stale_commit = vec![0xcf; 48];
    let stale_body = mls_recovery_add_body_v5(
        &origin_controller,
        &stale_recovery.device,
        scope,
        stale_submission,
        stale_key,
        1,
        bootstrap_head,
        stale_commit.clone(),
        stale_package_digest,
        stale_recovery.request_id,
        stale_recovery.request_digest,
    )?;
    let stale_request_digest = mls_recovery_add_request_digest_v5(
        &origin_controller,
        &stale_recovery.device,
        scope,
        stale_submission,
        stale_key,
        1,
        bootstrap_head,
        stale_commit,
        stale_package_digest,
        stale_recovery.request_id,
        stale_recovery.request_digest,
    )?;
    let stale = send_federated_mls_commit_v5(
        group_app.clone(),
        &stale_path,
        stale_key,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            1,
            scope,
            &stale_path,
            stale_submission,
            stale_request_digest,
            Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, stale_key.as_bytes()),
            900,
        )?,
        stale_body,
    )
    .await?;
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        v5_intent_count(group_harness.admin_pool(), tenant_id).await?,
        0
    );

    for (index, (candidate_package, request_digest, scope_digest)) in [
        (
            Sha256Digest::from_bytes([0xc1; 32]),
            recovery.request_digest,
            recovery.scope_digest,
        ),
        (
            package_digest,
            Sha256Digest::from_bytes([0xc2; 32]),
            recovery.scope_digest,
        ),
        (
            package_digest,
            recovery.request_digest,
            Sha256Digest::from_bytes([0xc3; 32]),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let submission_id = RequestId::new();
        let path = format!("{scope_path}/mls-commits/{submission_id}");
        let key = format!("federated-v5-mismatch-{index:04}");
        let commit = vec![0xc4_u8.saturating_add(u8::try_from(index)?); 48];
        let body = mls_recovery_add_body_v5_with_scope_digest(
            &origin_controller,
            &recovery.device,
            scope,
            submission_id,
            &key,
            1,
            bootstrap_head,
            commit.clone(),
            candidate_package,
            recovery.request_id,
            request_digest,
            scope_digest,
        )?;
        let request = mls_recovery_add_request_digest_v5_with_scope_digest(
            &origin_controller,
            &recovery.device,
            scope,
            submission_id,
            &key,
            1,
            bootstrap_head,
            commit,
            candidate_package,
            recovery.request_id,
            request_digest,
            scope_digest,
        )?;
        let rejected = send_federated_mls_commit_v5(
            group_app.clone(),
            &path,
            &key,
            &identity_origin,
            mls_commit_federated_proof(
                &origin_controller,
                &identity_origin,
                1,
                scope,
                &path,
                submission_id,
                request,
                Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, key.as_bytes()),
                950,
            )?,
            body,
        )
        .await?;
        assert!(
            matches!(
                rejected.status(),
                StatusCode::UNAUTHORIZED | StatusCode::UNPROCESSABLE_ENTITY
            ),
            "mismatch case {index} must fail closed"
        );
        assert_eq!(
            v5_intent_count(group_harness.admin_pool(), tenant_id).await?,
            0
        );
    }

    let add_submission = RequestId::new();
    let add_path = format!("{scope_path}/mls-commits/{add_submission}");
    let add_key = "federated-v5-add-0001";
    let add_commit = vec![0xd3; 48];
    let add_body = mls_recovery_add_body_v5(
        &origin_controller,
        &recovery.device,
        scope,
        add_submission,
        add_key,
        1,
        bootstrap_head,
        add_commit.clone(),
        package_digest,
        recovery.request_id,
        recovery.request_digest,
    )?;
    let add_request_digest = mls_recovery_add_request_digest_v5(
        &origin_controller,
        &recovery.device,
        scope,
        add_submission,
        add_key,
        1,
        bootstrap_head,
        add_commit,
        package_digest,
        recovery.request_id,
        recovery.request_digest,
    )?;
    let add_idempotency_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, add_key.as_bytes());
    let added = send_federated_mls_commit_v5(
        group_app.clone(),
        &add_path,
        add_key,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            1,
            scope,
            &add_path,
            add_submission,
            add_request_digest,
            add_idempotency_hash,
            1_000,
        )?,
        add_body.clone(),
    )
    .await?;
    assert_eq!(added.status(), StatusCode::CREATED);
    assert_content_type(&added, MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE);
    let add_receipt = response_bytes(added).await?;
    let (add_receipt_digest, add_head) = mls_receipt_facts(&add_receipt)?;

    let add_replay = send_federated_mls_commit_v5(
        group_app.clone(),
        &add_path,
        add_key,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            1,
            scope,
            &add_path,
            add_submission,
            add_request_digest,
            add_idempotency_hash,
            1_100,
        )?,
        add_body,
    )
    .await?;
    assert_eq!(add_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(add_replay).await?, add_receipt);
    let add_readback = send_federated_mls_receipt_query_v5(
        group_app.clone(),
        &add_path,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            2,
            scope,
            &add_path,
            add_submission,
            add_request_digest,
            add_idempotency_hash,
            1_200,
        )?,
    )
    .await?;
    assert_eq!(add_readback.status(), StatusCode::OK);
    assert_eq!(response_bytes(add_readback).await?, add_receipt);

    let confirmation_path = format!("{add_path}/confirmations/{}", recovery.device.device_id);
    let confirmation_body = mls_confirmation_body(
        &recovery.device,
        add_submission,
        add_receipt_digest,
        add_head,
    )?;
    let confirmation = send_federated_confirmation(
        group_app.clone(),
        &confirmation_path,
        &identity_origin,
        mls_confirmation_proof(
            &recovery.device,
            &identity_origin,
            scope,
            &confirmation_path,
            add_submission,
            &confirmation_body,
            1_300,
        )?,
        confirmation_body,
    )
    .await?;
    assert_eq!(confirmation.status(), StatusCode::NO_CONTENT);

    let revoke_head = revoke_device_over_http(
        identity_app,
        &origin_store,
        &origin_controller,
        recovery.device.device_id,
        "federated-v5-revoke-0001",
        NOW,
    )
    .await?;
    let wrong_remove_submission = RequestId::new();
    let wrong_remove_path = format!("{scope_path}/mls-commits/{wrong_remove_submission}");
    let wrong_remove_key = "federated-v5-wrong-revoke-target-0001";
    let wrong_remove_commit = vec![0xce; 48];
    let wrong_remove_body = mls_device_remove_body_v5(
        &origin_controller,
        &stale_recovery.device,
        scope,
        wrong_remove_submission,
        wrong_remove_key,
        2,
        add_head,
        wrong_remove_commit.clone(),
        revoke_head,
    )?;
    let wrong_remove_request = mls_device_remove_request_digest_v5(
        &origin_controller,
        &stale_recovery.device,
        scope,
        wrong_remove_submission,
        wrong_remove_key,
        2,
        add_head,
        wrong_remove_commit,
        revoke_head,
    )?;
    let wrong_remove = send_federated_mls_commit_v5(
        group_app.clone(),
        &wrong_remove_path,
        wrong_remove_key,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            1,
            scope,
            &wrong_remove_path,
            wrong_remove_submission,
            wrong_remove_request,
            Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, wrong_remove_key.as_bytes()),
            1_350,
        )?,
        wrong_remove_body,
    )
    .await?;
    assert_eq!(wrong_remove.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        v5_intent_count(group_harness.admin_pool(), tenant_id).await?,
        1
    );
    let remove_submission = RequestId::new();
    let remove_path = format!("{scope_path}/mls-commits/{remove_submission}");
    let remove_key = "federated-v5-remove-0001";
    let remove_commit = vec![0xd4; 48];
    let remove_body = mls_device_remove_body_v5(
        &origin_controller,
        &recovery.device,
        scope,
        remove_submission,
        remove_key,
        2,
        add_head,
        remove_commit.clone(),
        revoke_head,
    )?;
    let remove_request_digest = mls_device_remove_request_digest_v5(
        &origin_controller,
        &recovery.device,
        scope,
        remove_submission,
        remove_key,
        2,
        add_head,
        remove_commit,
        revoke_head,
    )?;
    let remove_idempotency_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, remove_key.as_bytes());
    let removed = send_federated_mls_commit_v5(
        group_app.clone(),
        &remove_path,
        remove_key,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            1,
            scope,
            &remove_path,
            remove_submission,
            remove_request_digest,
            remove_idempotency_hash,
            1_400,
        )?,
        remove_body.clone(),
    )
    .await?;
    assert_eq!(removed.status(), StatusCode::CREATED);
    assert_content_type(&removed, MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE);
    let remove_receipt = response_bytes(removed).await?;
    let remove_replay = send_federated_mls_commit_v5(
        group_app.clone(),
        &remove_path,
        remove_key,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            1,
            scope,
            &remove_path,
            remove_submission,
            remove_request_digest,
            remove_idempotency_hash,
            1_500,
        )?,
        remove_body,
    )
    .await?;
    assert_eq!(remove_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(remove_replay).await?, remove_receipt);
    let remove_readback = send_federated_mls_receipt_query_v5(
        group_app,
        &remove_path,
        &identity_origin,
        mls_commit_federated_proof(
            &origin_controller,
            &identity_origin,
            2,
            scope,
            &remove_path,
            remove_submission,
            remove_request_digest,
            remove_idempotency_hash,
            1_600,
        )?,
    )
    .await?;
    assert_eq!(remove_readback.status(), StatusCode::OK);
    assert_eq!(response_bytes(remove_readback).await?, remove_receipt);

    let group_identity_after = IdentityLogRepository::new()
        .load(&group_identity_store, origin_controller.identity_id)
        .await?
        .ok_or("group-side identity disappeared")?;
    assert_eq!(group_identity_after.head().sequence().get(), 2);
    assert_eq!(
        group_identity_after
            .projection()
            .device_status(recovery.device.device_id),
        None
    );
    assert_eq!(
        v5_intent_count(group_harness.admin_pool(), tenant_id).await?,
        2
    );
    identity_server.abort();
    Ok(())
}
