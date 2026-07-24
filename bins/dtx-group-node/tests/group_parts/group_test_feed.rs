#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn active_member_fetches_consecutive_v30_v32_feed_and_removed_member_converges()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 6).await?;
    let group_store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let owner = enroll_active_device(&identity_store, 111, 112, 113, [114; 32]).await?;
    let member = enroll_active_device(&identity_store, 115, 116, 117, [118; 32]).await?;
    let peer = enroll_active_device(&identity_store, 119, 120, 121, [122; 32]).await?;
    let outsider = enroll_active_device(&identity_store, 123, 124, 125, [126; 32]).await?;
    let tenant_id = TenantId::new();
    let app = group_router_with_state(
        GroupNodeState::with_clock(group_store.clone(), tenant_id, Arc::new(FixedClock(NOW)))
            .with_mls_sequencer_signing_key(SigningKey::from_bytes(&[127; 32]))
            .with_public_origin_and_allowed_http_identity_origins(
                AUDIENCE,
                std::iter::empty::<String>(),
            )?,
    );
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let create_key = "commit-feed-create-0001";
    let create = send_mutation(
        app.clone(),
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
    let bootstrap_key = "commit-feed-bootstrap-0001";
    let bootstrap = send_mutation(
        app.clone(),
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
    let bootstrap_confirmation_path = format!("{bootstrap_path}/confirmations/{}", owner.device_id);
    let bootstrap_confirmation = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&bootstrap_confirmation_path)
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

    let (member_receipt, member_head) = admit_local_v30_member(
        app.clone(),
        &owner,
        &member,
        scope,
        &scope_path,
        Revision::INITIAL,
        1,
        bootstrap_head,
        vec![0x52; 48],
        "commit-feed-member",
    )
    .await?;
    assert_eq!(mls_receipt_epoch(&member_receipt)?, 2);
    let grant_revision = GroupMembershipRepository
        .load_policy(&group_store, tenant_id, scope)
        .await?
        .revision();
    let grant_path = format!("{scope_path}/admins/{}", member.identity_id);
    let grant_key = "commit-feed-grant-admin-0001";
    let grant = send_mutation(
        app.clone(),
        "PUT",
        &grant_path,
        GROUP_GRANT_ADMIN_CONTENT_TYPE,
        grant_key,
        &owner,
        grant_admin_body(
            &owner,
            scope,
            &grant_path,
            grant_key,
            1_050,
            grant_revision,
            member.identity_id,
        )?,
    )
    .await?;
    assert_eq!(grant.status(), StatusCode::CREATED);
    let next_revision = GroupMembershipRepository
        .load_policy(&group_store, tenant_id, scope)
        .await?
        .revision();
    let peer_commit = vec![0x63; 48];
    let (peer_receipt, peer_head) = admit_local_v30_member(
        app.clone(),
        &owner,
        &peer,
        scope,
        &scope_path,
        next_revision,
        2,
        member_head,
        peer_commit.clone(),
        "commit-feed-peer",
    )
    .await?;
    assert_eq!(mls_receipt_epoch(&peer_receipt)?, 3);

    let target = format!("{scope_path}/mls-commits?after_epoch=2&limit=64");
    let wrong_feed_action = send_local_commit_feed(
        app.clone(),
        &target,
        &member,
        group_query_proof_for_action(&member, AUDIENCE, scope, &target, 1, 1_100)?,
    )
    .await?;
    assert_eq!(wrong_feed_action.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let feed = send_local_commit_feed(
        app.clone(),
        &target,
        &member,
        group_query_proof_for_action(&member, AUDIENCE, scope, &target, 2, 1_100)?,
    )
    .await?;
    assert_eq!(feed.status(), StatusCode::OK);
    assert_content_type(&feed, MLS_COMMIT_FEED_CONTENT_TYPE);
    assert_eq!(
        feed.headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let feed_bytes = response_bytes(feed).await?;
    let items = decode_commit_feed(&feed_bytes, 1, 2)?;
    assert_eq!(items, vec![(peer_receipt.clone(), peer_commit.clone())]);

    let caught_up_target = format!("{scope_path}/mls-commits?after_epoch=3&limit=64");
    let caught_up = send_local_commit_feed(
        app.clone(),
        &caught_up_target,
        &member,
        group_query_proof_for_action(&member, AUDIENCE, scope, &caught_up_target, 2, 1_200)?,
    )
    .await?;
    assert_eq!(caught_up.status(), StatusCode::OK);
    assert!(decode_commit_feed(&response_bytes(caught_up).await?, 1, 3)?.is_empty());

    let denied = send_local_commit_feed(
        app.clone(),
        &target,
        &outsider,
        group_query_proof_for_action(&outsider, AUDIENCE, scope, &target, 2, 1_300)?,
    )
    .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(
        denied
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(MLS_COMMIT_FEED_CONTENT_TYPE)
    );

    let removal_revision = GroupMembershipRepository
        .load_policy(&group_store, tenant_id, scope)
        .await?
        .revision();
    let scope_id = scope_path.rsplit('/').next().ok_or("scope id")?;
    let removal_preconditions: (i64, String, bool, i64, bool, i64, Vec<u8>) = sqlx::query_as(
        "SELECT policy.policy_revision,policy.owner_identity_id,
                EXISTS (SELECT 1 FROM groups.members member
                         WHERE member.tenant_id=policy.tenant_id
                           AND member.scope_kind=policy.scope_kind
                           AND member.scope_id=policy.scope_id AND member.identity_id=$3),
                (SELECT count(*) FROM groups.mls_device_members leaf
                  WHERE leaf.tenant_id=policy.tenant_id AND leaf.scope_kind=policy.scope_kind
                    AND leaf.scope_id=policy.scope_id AND leaf.identity_id=$3
                    AND leaf.state IN ('pending_confirmation','active')),
                EXISTS (SELECT 1 FROM groups.mls_device_members leaf
                         WHERE leaf.tenant_id=policy.tenant_id
                           AND leaf.scope_kind=policy.scope_kind
                           AND leaf.scope_id=policy.scope_id AND leaf.identity_id=$3
                           AND leaf.device_id=$4 AND leaf.state='active'),
                head.epoch,head.head_digest
           FROM groups.policy_heads policy
           JOIN groups.mls_heads head USING (tenant_id,scope_kind,scope_id)
          WHERE policy.tenant_id=$1 AND policy.scope_kind='private_conversation'
            AND policy.scope_id=$2",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .bind(scope_id)
    .bind(peer.identity_id.to_string())
    .bind(uuid::Uuid::from(peer.device_id))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(
        removal_preconditions.0,
        i64::try_from(removal_revision.get())?
    );
    assert_eq!(removal_preconditions.1, owner.identity_id.to_string());
    assert!(removal_preconditions.2);
    assert_eq!(removal_preconditions.3, 1);
    assert!(removal_preconditions.4);
    assert_eq!(removal_preconditions.5, 3);
    assert_eq!(removal_preconditions.6, peer_head.as_bytes());
    let admin_submission = RequestId::new();
    let admin_path = format!("{scope_path}/mls-commits/{admin_submission}");
    let admin_attempt = send_mutation(
        app.clone(),
        "POST",
        &admin_path,
        MLS_COMMIT_V4_CONTENT_TYPE,
        "commit-feed-admin-remove-0001",
        &member,
        mls_commit_body_v4(
            &member,
            &peer,
            scope,
            admin_submission,
            3,
            peer_head,
            removal_revision,
            vec![0x74; 48],
        )?,
    )
    .await?;
    assert_eq!(admin_attempt.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let removal_submission = RequestId::new();
    let removal_path = format!("{scope_path}/mls-commits/{removal_submission}");
    let removal_key = "commit-feed-owner-remove-0001";
    let removal_body = mls_commit_body_v4(
        &owner,
        &peer,
        scope,
        removal_submission,
        3,
        peer_head,
        removal_revision,
        vec![0x75; 48],
    )?;
    let removed = send_mutation(
        app.clone(),
        "POST",
        &removal_path,
        MLS_COMMIT_V4_CONTENT_TYPE,
        removal_key,
        &owner,
        removal_body.clone(),
    )
    .await?;
    assert_eq!(removed.status(), StatusCode::CREATED);
    assert_content_type(&removed, MLS_COMMIT_RECEIPT_V4_CONTENT_TYPE);
    let removal_receipt = response_bytes(removed).await?;
    assert_eq!(mls_receipt_epoch(&removal_receipt)?, 4);

    let replay = send_mutation(
        app.clone(),
        "POST",
        &removal_path,
        MLS_COMMIT_V4_CONTENT_TYPE,
        removal_key,
        &owner,
        removal_body,
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(replay).await?, removal_receipt);
    let conflict = send_mutation(
        app.clone(),
        "POST",
        &removal_path,
        MLS_COMMIT_V4_CONTENT_TYPE,
        removal_key,
        &owner,
        mls_commit_body_v4(
            &owner,
            &peer,
            scope,
            removal_submission,
            3,
            peer_head,
            removal_revision,
            vec![0x76; 48],
        )?,
    )
    .await?;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);

    let removal_target = format!("{scope_path}/mls-commits?after_epoch=3&limit=64");
    let legacy_feed = send_local_commit_feed(
        app.clone(),
        &removal_target,
        &owner,
        group_query_proof_for_action(&owner, AUDIENCE, scope, &removal_target, 2, 1_400)?,
    )
    .await?;
    assert_eq!(legacy_feed.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let final_feed = send_local_commit_feed_v2(
        app.clone(),
        &removal_target,
        &peer,
        group_query_proof_for_action(&peer, AUDIENCE, scope, &removal_target, 2, 1_500)?,
    )
    .await?;
    assert_eq!(final_feed.status(), StatusCode::OK);
    assert_content_type(&final_feed, MLS_COMMIT_FEED_V2_CONTENT_TYPE);
    let final_items = decode_commit_feed(&response_bytes(final_feed).await?, 2, 3)?;
    assert_eq!(final_items.len(), 1);
    assert_eq!(final_items[0].0, removal_receipt);
    let after_removal_target = format!("{scope_path}/mls-commits?after_epoch=4&limit=64");
    let removed_access = send_local_commit_feed_v2(
        app,
        &after_removal_target,
        &peer,
        group_query_proof_for_action(&peer, AUDIENCE, scope, &after_removal_target, 2, 1_600)?,
    )
    .await?;
    assert_eq!(removed_access.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}
