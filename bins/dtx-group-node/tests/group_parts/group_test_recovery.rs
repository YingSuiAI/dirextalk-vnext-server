#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one V40 boundary test keeps identity-head freshness, scoped package consumption, confirmation, revocation, replay, and feed order coherent"
)]
async fn v5_recovery_add_and_revoked_leaf_removal_are_http_replay_safe()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let group_store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let owner = enroll_active_device(&identity_store, 131, 132, 133, [134; 32]).await?;
    let identity_app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            identity_store.clone(),
            Arc::new(FixedClock(NOW)),
            AUDIENCE,
        ),
    );
    let tenant_id = TenantId::new();
    let group_app = group_router_with_state(
        GroupNodeState::with_clock(group_store.clone(), tenant_id, Arc::new(FixedClock(NOW)))
            .with_mls_sequencer_signing_key(SigningKey::from_bytes(&[135; 32]))
            .with_public_origin_and_allowed_http_identity_origins(
                AUDIENCE,
                std::iter::empty::<String>(),
            )?,
    );
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let create_key = "v5-recovery-group-create-0001";
    let create = send_mutation(
        group_app.clone(),
        "PUT",
        &scope_path,
        GROUP_CREATE_CONTENT_TYPE,
        create_key,
        &owner,
        create_body(&owner, scope, &scope_path, create_key, 1_000)?,
    )
    .await?;
    assert_eq!(create.status(), StatusCode::CREATED);

    let bootstrap_submission = RequestId::new();
    let bootstrap_path = format!("{scope_path}/mls-commits/{bootstrap_submission}");
    let bootstrap_key = "v5-recovery-bootstrap-0001";
    let bootstrap = send_mutation(
        group_app.clone(),
        "POST",
        &bootstrap_path,
        MLS_COMMIT_CONTENT_TYPE,
        bootstrap_key,
        &owner,
        mls_commit_body(
            &owner,
            &owner,
            scope,
            bootstrap_submission,
            bootstrap_key,
            0,
            Sha256Digest::from_bytes([0; 32]),
            vec![0x41; 48],
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
                    owner.device_id
                ))
                .header(header::CONTENT_TYPE, MLS_CONFIRMATION_CONTENT_TYPE)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(owner.session_id, owner.session_secret),
                )
                .body(Body::from(mls_confirmation_body(
                    &owner,
                    bootstrap_submission,
                    bootstrap_receipt_digest,
                    bootstrap_head,
                )?))?,
        )
        .await?;
    assert_eq!(bootstrap_confirmation.status(), StatusCode::NO_CONTENT);

    let recovery_a = prepare_scoped_history_recovery(
        identity_app.clone(),
        &identity_store,
        &owner,
        scope,
        136,
        137,
        [138; 32],
        [139; 32],
        "v5-history-recovery-a",
        NOW - 200,
    )
    .await?;
    let recovery_b = prepare_scoped_history_recovery(
        identity_app.clone(),
        &identity_store,
        &owner,
        scope,
        140,
        141,
        [142; 32],
        [143; 32],
        "v5-history-recovery-b",
        NOW - 100,
    )
    .await?;
    let current_identity_head = IdentityLogRepository::new()
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing after recovery approvals")?
        .head();
    assert_ne!(recovery_a.approved_head, current_identity_head);
    assert_eq!(recovery_b.approved_head, current_identity_head);

    // Both packages are deliberately published at B's current identity head.
    // A can therefore fail only because its approved recovery head is stale.
    let package_a = publish_scoped_recovery_key_package(
        identity_app.clone(),
        &owner,
        &recovery_a,
        scope,
        current_identity_head,
        vec![0xa1; 64],
        "v5-scoped-package-a-0001",
    )
    .await?;
    let package_b = publish_scoped_recovery_key_package(
        identity_app.clone(),
        &owner,
        &recovery_b,
        scope,
        current_identity_head,
        vec![0xb1; 64],
        "v5-scoped-package-b-0001",
    )
    .await?;

    let stale_submission = RequestId::new();
    let stale_path = format!("{scope_path}/mls-commits/{stale_submission}");
    let stale_key = "v5-stale-recovery-add-0001";
    let stale = send_mutation(
        group_app.clone(),
        "POST",
        &stale_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        stale_key,
        &owner,
        mls_recovery_add_body_v5(
            &owner,
            &recovery_a.device,
            scope,
            stale_submission,
            stale_key,
            1,
            bootstrap_head,
            vec![0xa2; 48],
            package_a,
            recovery_a.request_id,
            recovery_a.request_digest,
        )?,
    )
    .await?;
    assert_eq!(stale.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_safe_group_error(stale, "GROUP_ACTION_PROOF_INVALID").await?;
    assert_eq!(v5_intent_count(harness.admin_pool(), tenant_id).await?, 0);

    let add_submission = RequestId::new();
    let add_path = format!("{scope_path}/mls-commits/{add_submission}");
    let add_key = "v5-current-recovery-add-0001";
    let add_commit = vec![0xb2; 48];
    let add_body = mls_recovery_add_body_v5(
        &owner,
        &recovery_b.device,
        scope,
        add_submission,
        add_key,
        1,
        bootstrap_head,
        add_commit.clone(),
        package_b,
        recovery_b.request_id,
        recovery_b.request_digest,
    )?;
    let added = send_mutation(
        group_app.clone(),
        "POST",
        &add_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        add_key,
        &owner,
        add_body.clone(),
    )
    .await?;
    assert_eq!(added.status(), StatusCode::CREATED);
    assert_content_type(&added, MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE);
    let add_receipt = response_bytes(added).await?;
    assert_eq!(mls_receipt_epoch(&add_receipt)?, 2);
    let (add_receipt_digest, add_head) = mls_receipt_facts(&add_receipt)?;

    let add_replay = send_mutation(
        group_app.clone(),
        "POST",
        &add_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        add_key,
        &owner,
        add_body,
    )
    .await?;
    assert_eq!(add_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(add_replay).await?, add_receipt);
    let add_conflict = send_mutation(
        group_app.clone(),
        "POST",
        &add_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        add_key,
        &owner,
        mls_recovery_add_body_v5(
            &owner,
            &recovery_b.device,
            scope,
            add_submission,
            add_key,
            1,
            bootstrap_head,
            vec![0xb3; 48],
            package_b,
            recovery_b.request_id,
            recovery_b.request_digest,
        )?,
    )
    .await?;
    assert_eq!(add_conflict.status(), StatusCode::CONFLICT);

    let add_confirmation_path = format!("{add_path}/confirmations/{}", recovery_b.device.device_id);
    let add_confirmation = group_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&add_confirmation_path)
                .header(header::CONTENT_TYPE, MLS_CONFIRMATION_V3_CONTENT_TYPE)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(
                        recovery_b.device.session_id,
                        recovery_b.device.session_secret,
                    ),
                )
                .body(Body::from(mls_confirmation_body(
                    &recovery_b.device,
                    add_submission,
                    add_receipt_digest,
                    add_head,
                )?))?,
        )
        .await?;
    assert_eq!(add_confirmation.status(), StatusCode::NO_CONTENT);
    let scope_id = scope_path.rsplit('/').next().ok_or("scope id")?;
    let recovered_leaf_state: String = sqlx::query_scalar(
        "SELECT state FROM groups.mls_device_members
          WHERE tenant_id=$1 AND scope_kind='private_conversation' AND scope_id=$2
            AND identity_id=$3 AND device_id=$4",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .bind(scope_id)
    .bind(owner.identity_id.to_string())
    .bind(uuid::Uuid::from(recovery_b.device.device_id))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(recovered_leaf_state, "active");

    let pre_revoke_identity_head = IdentityLogRepository::new()
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity missing before recovery leaf revoke")?
        .head();
    let before_revoke_submission = RequestId::new();
    let before_revoke_path = format!("{scope_path}/mls-commits/{before_revoke_submission}");
    let before_revoke_key = "v5-remove-before-revoke-0001";
    let before_revoke = send_mutation(
        group_app.clone(),
        "POST",
        &before_revoke_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        before_revoke_key,
        &owner,
        mls_device_remove_body_v5(
            &owner,
            &recovery_b.device,
            scope,
            before_revoke_submission,
            before_revoke_key,
            2,
            add_head,
            vec![0xc1; 48],
            pre_revoke_identity_head.hash(),
        )?,
    )
    .await?;
    assert_eq!(before_revoke.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_safe_group_error(before_revoke, "GROUP_ACTION_PROOF_INVALID").await?;
    assert_eq!(v5_intent_count(harness.admin_pool(), tenant_id).await?, 1);

    let revoke_head = revoke_device_over_http(
        identity_app,
        &identity_store,
        &owner,
        recovery_b.device.device_id,
        "v5-revoke-recovered-device-0001",
        NOW,
    )
    .await?;

    let mismatched_submission = RequestId::new();
    let mismatched_path = format!("{scope_path}/mls-commits/{mismatched_submission}");
    let mismatched_key = "v5-remove-mismatched-target-0001";
    let mismatched = send_mutation(
        group_app.clone(),
        "POST",
        &mismatched_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        mismatched_key,
        &owner,
        mls_device_remove_body_v5(
            &owner,
            &recovery_a.device,
            scope,
            mismatched_submission,
            mismatched_key,
            2,
            add_head,
            vec![0xc2; 48],
            revoke_head,
        )?,
    )
    .await?;
    assert_eq!(mismatched.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_safe_group_error(mismatched, "GROUP_ACTION_PROOF_INVALID").await?;
    assert_eq!(v5_intent_count(harness.admin_pool(), tenant_id).await?, 1);

    let remove_submission = RequestId::new();
    let remove_path = format!("{scope_path}/mls-commits/{remove_submission}");
    let remove_key = "v5-remove-current-target-0001";
    let remove_commit = vec![0xc3; 48];
    let remove_body = mls_device_remove_body_v5(
        &owner,
        &recovery_b.device,
        scope,
        remove_submission,
        remove_key,
        2,
        add_head,
        remove_commit.clone(),
        revoke_head,
    )?;
    let removed = send_mutation(
        group_app.clone(),
        "POST",
        &remove_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        remove_key,
        &owner,
        remove_body.clone(),
    )
    .await?;
    assert_eq!(removed.status(), StatusCode::CREATED);
    assert_content_type(&removed, MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE);
    let remove_receipt = response_bytes(removed).await?;
    assert_eq!(mls_receipt_epoch(&remove_receipt)?, 3);

    let remove_replay = send_mutation(
        group_app.clone(),
        "POST",
        &remove_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        remove_key,
        &owner,
        remove_body,
    )
    .await?;
    assert_eq!(remove_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(remove_replay).await?, remove_receipt);
    let remove_conflict = send_mutation(
        group_app.clone(),
        "POST",
        &remove_path,
        MLS_COMMIT_V5_CONTENT_TYPE,
        remove_key,
        &owner,
        mls_device_remove_body_v5(
            &owner,
            &recovery_b.device,
            scope,
            remove_submission,
            remove_key,
            2,
            add_head,
            vec![0xc4; 48],
            revoke_head,
        )?,
    )
    .await?;
    assert_eq!(remove_conflict.status(), StatusCode::CONFLICT);

    let feed_target = format!("{scope_path}/mls-commits?after_epoch=1&limit=64");
    let feed = send_local_commit_feed_v3(
        group_app,
        &feed_target,
        &owner,
        group_query_proof_for_action(&owner, AUDIENCE, scope, &feed_target, 2, 1_900)?,
    )
    .await?;
    assert_eq!(feed.status(), StatusCode::OK);
    assert_content_type(&feed, MLS_COMMIT_FEED_V3_CONTENT_TYPE);
    assert_eq!(
        decode_commit_feed(&response_bytes(feed).await?, 3, 1)?,
        vec![(add_receipt, add_commit), (remove_receipt, remove_commit)]
    );
    assert_eq!(v5_intent_count(harness.admin_pool(), tenant_id).await?, 2);
    let v5_receipt_rows: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM groups.mls_commit_receipts AS receipt
           JOIN groups.mls_commit_intents AS intent
             USING (tenant_id,submission_id)
          WHERE receipt.tenant_id=$1 AND intent.protocol_version=5",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(v5_receipt_rows, 2);
    Ok(())
}
