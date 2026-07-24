#[tokio::test]
#[allow(clippy::too_many_lines)] // The end-to-end recovery scenario intentionally keeps its user-visible sequence together.
async fn group_http_replays_refreshed_proofs_and_preserves_membership_intents()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let group_store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let tenant_id = TenantId::new();
    let owner = enroll_active_device(&identity_store, 11, 12, 13, [14; 32]).await?;
    let candidate = enroll_active_device(&identity_store, 21, 22, 23, [24; 32]).await?;
    let (candidate_origin, identity_server) =
        start_identity_log_server(identity_store.clone()).await?;
    let app = group_router_with_state(
        GroupNodeState::with_clock(group_store, tenant_id, Arc::new(FixedClock(NOW)))
            .with_mls_sequencer_signing_key(SigningKey::from_bytes(&[99; 32]))
            .with_public_origin_and_allowed_http_identity_origins(
                AUDIENCE,
                [candidate_origin.clone()],
            )?,
    );
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let create_idempotency_key = "group-create-replay-0001";
    let first_create_body = create_body(&owner, scope, &scope_path, create_idempotency_key, 1_000)?;
    let first_create = send_mutation(
        app.clone(),
        "PUT",
        &scope_path,
        GROUP_CREATE_CONTENT_TYPE,
        create_idempotency_key,
        &owner,
        first_create_body,
    )
    .await?;
    assert_eq!(first_create.status(), StatusCode::CREATED);
    assert_content_type(&first_create, GROUP_ACTION_RECEIPT_CONTENT_TYPE);
    let first_create_receipt = response_bytes(first_create).await?;

    // The retry uses a freshly issued proof and signature but the same logical
    // action/key. The stored receipt must be replayed byte-for-byte instead
    // of being mistaken for a divergent command after a lost response.
    let refreshed_create = send_mutation(
        app.clone(),
        "PUT",
        &scope_path,
        GROUP_CREATE_CONTENT_TYPE,
        create_idempotency_key,
        &owner,
        create_body(&owner, scope, &scope_path, create_idempotency_key, 1_500)?,
    )
    .await?;
    assert_eq!(refreshed_create.status(), StatusCode::OK);
    assert_eq!(
        response_bytes(refreshed_create).await?,
        first_create_receipt
    );

    let bootstrap_submission = RequestId::new();
    let bootstrap_path = format!("{scope_path}/mls-commits/{bootstrap_submission}");
    let bootstrap_key = "mls-owner-bootstrap-0001";
    let bootstrap_body = mls_commit_body(
        &owner,
        &owner,
        scope,
        bootstrap_submission,
        bootstrap_key,
        0,
        Sha256Digest::from_bytes([0; 32]),
        vec![0x41; 48],
        MlsCommitAuthorization::OwnerBootstrap,
    )?;
    let bootstrap = send_mutation(
        app.clone(),
        "POST",
        &bootstrap_path,
        MLS_COMMIT_CONTENT_TYPE,
        bootstrap_key,
        &owner,
        bootstrap_body.clone(),
    )
    .await?;
    assert_eq!(bootstrap.status(), StatusCode::CREATED);
    assert_content_type(&bootstrap, MLS_COMMIT_RECEIPT_CONTENT_TYPE);
    let bootstrap_receipt = response_bytes(bootstrap).await?;
    let bootstrap_head = mls_receipt_head(&bootstrap_receipt)?;
    let bootstrap_replay = send_mutation(
        app.clone(),
        "POST",
        &bootstrap_path,
        MLS_COMMIT_CONTENT_TYPE,
        bootstrap_key,
        &owner,
        bootstrap_body,
    )
    .await?;
    assert_eq!(bootstrap_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(bootstrap_replay).await?, bootstrap_receipt);

    let invite_id = InviteCapabilityId::new();
    let invite_path = format!("{scope_path}/invites/{invite_id}");
    let invite_key = "group-issue-invite-0001";
    let invite_body = issue_invite_body(
        &owner,
        scope,
        &invite_path,
        invite_key,
        1_000,
        Revision::INITIAL,
        Some(candidate.identity_id),
        1,
        10_000,
    )?;
    let invite = send_mutation(
        app.clone(),
        "PUT",
        &invite_path,
        GROUP_ISSUE_INVITE_CONTENT_TYPE,
        invite_key,
        &owner,
        invite_body,
    )
    .await?;
    assert_eq!(invite.status(), StatusCode::CREATED);

    let join_request_id = JoinRequestId::new();
    let join_command_id = RequestId::new();
    let join_path = format!("{scope_path}/join-requests/{join_request_id}");
    let join_key = "group-join-request-0001";
    let candidate_key_package_digest = test_candidate_key_package_digest(&candidate);
    let join_body = join_request_body_v2(
        &candidate,
        scope,
        &join_path,
        join_key,
        1_000,
        join_command_id,
        invite_id,
        Revision::new(2)?,
        Sha256Digest::hash_domain(b"test-group-head\0", b"join"),
        candidate_key_package_digest,
    )?;
    let join = send_mutation(
        app.clone(),
        "PUT",
        &join_path,
        GROUP_JOIN_REQUEST_V2_CONTENT_TYPE,
        join_key,
        &candidate,
        join_body.clone(),
    )
    .await?;
    assert_eq!(join.status(), StatusCode::ACCEPTED);
    let join_receipt = response_bytes(join).await?;
    assert_membership_phase(&join_receipt, 1)?;
    let join_request_digest = membership_receipt_request_digest(&join_receipt)?;
    let join_replay = send_mutation(
        app.clone(),
        "PUT",
        &join_path,
        GROUP_JOIN_REQUEST_V2_CONTENT_TYPE,
        join_key,
        &candidate,
        join_body,
    )
    .await?;
    assert_eq!(join_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(join_replay).await?, join_receipt);

    let pending_target = format!("{scope_path}/join-requests?after=&limit=32");
    let pending_v2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&pending_target)
                .header(header::ACCEPT, GROUP_JOIN_REQUEST_PAGE_V2_CONTENT_TYPE)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(owner.session_id, owner.session_secret),
                )
                .header(
                    GROUP_QUERY_PROOF_HEADER,
                    group_query_proof(&owner, AUDIENCE, scope, &pending_target, 1_100)?,
                )
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(pending_v2.status(), StatusCode::OK);
    assert_content_type(&pending_v2, GROUP_JOIN_REQUEST_PAGE_V2_CONTENT_TYPE);
    let (pending_join_request_id, pending_key_package_digest) =
        decode_v2_pending_package(&response_bytes(pending_v2).await?)?;
    assert_eq!(pending_join_request_id, join_request_id.to_string());
    assert_eq!(pending_key_package_digest, candidate_key_package_digest);

    let mismatched_accept = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&pending_target)
                .header(header::ACCEPT, MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE)
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(owner.session_id, owner.session_secret),
                )
                .header(
                    GROUP_QUERY_PROOF_HEADER,
                    group_query_proof(&owner, AUDIENCE, scope, &pending_target, 1_150)?,
                )
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(mismatched_accept.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let approval_command_id = RequestId::new();
    let approval_path = format!("{join_path}/approvals");
    let approval_key = "group-approve-join-0001";
    let approval_body = approve_join_body_v2(
        &owner,
        scope,
        &approval_path,
        approval_key,
        1_000,
        approval_command_id,
        candidate.identity_id,
        candidate.device_id,
        invite_id,
        Revision::new(3)?,
        bootstrap_head,
        candidate_key_package_digest,
    )?;
    let authorization_digest = action_proof_binding_digest(&approval_body)?;
    let approval = send_mutation(
        app.clone(),
        "POST",
        &approval_path,
        GROUP_APPROVE_JOIN_V2_CONTENT_TYPE,
        approval_key,
        &owner,
        approval_body.clone(),
    )
    .await?;
    assert_eq!(approval.status(), StatusCode::ACCEPTED);
    assert_content_type(&approval, MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE);
    let approval_receipt = response_bytes(approval).await?;
    assert_membership_phase(&approval_receipt, 2)?;
    let approval_request_digest = membership_receipt_request_digest(&approval_receipt)?;
    let approval_replay = send_mutation(
        app.clone(),
        "POST",
        &approval_path,
        GROUP_APPROVE_JOIN_V2_CONTENT_TYPE,
        approval_key,
        &owner,
        approval_body,
    )
    .await?;
    assert_eq!(approval_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(approval_replay).await?, approval_receipt);

    let membership_command_id =
        dtx_membership_command::MembershipCommandId::new(approval_command_id);
    let join_submission = RequestId::new();
    let join_commit_path = format!("{scope_path}/mls-commits/{join_submission}");
    let join_commit_key = "mls-approved-join-0001";
    let join_commit_body = mls_commit_body_v3(
        &owner,
        &candidate,
        scope,
        join_submission,
        1,
        bootstrap_head,
        vec![0x52; 48],
        membership_command_id,
        authorization_digest,
        join_request_digest,
        approval_request_digest,
        candidate_key_package_digest,
    )?;
    let join_commit_request_digest = mls_v3_request_digest(&join_commit_body)?;
    let join_commit_key_hash =
        Sha256Digest::hash_domain(MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, join_commit_key.as_bytes());

    // Every signed mismatch is rejected before any sequencer state can be
    // written. This protects exact body/request/path/origin/action binding.
    let mut tampered_body = join_commit_body.clone();
    let CanonicalValue::Map(tampered_fields) = decode_deterministic_cbor(&tampered_body)? else {
        return Err("V3 MLS commit body must be a map".into());
    };
    let mut tampered_fields = tampered_fields;
    tampered_fields[13].1 = Sha256Digest::from_bytes([0x29; 32]).to_canonical_value();
    tampered_body = encode(&CanonicalValue::Map(tampered_fields))?;
    let valid_submit_proof = mls_commit_federated_proof(
        &owner,
        &candidate_origin,
        1,
        scope,
        &join_commit_path,
        join_submission,
        join_commit_request_digest,
        join_commit_key_hash,
        1_000,
    )?;
    for (label, body, proof) in [
        ("body", tampered_body, valid_submit_proof.clone()),
        (
            "request digest",
            join_commit_body.clone(),
            mls_commit_federated_proof(
                &owner,
                &candidate_origin,
                1,
                scope,
                &join_commit_path,
                join_submission,
                Sha256Digest::from_bytes([0x31; 32]),
                join_commit_key_hash,
                1_000,
            )?,
        ),
        (
            "path",
            join_commit_body.clone(),
            mls_commit_federated_proof(
                &owner,
                &candidate_origin,
                1,
                scope,
                &format!("{join_commit_path}/tampered"),
                join_submission,
                join_commit_request_digest,
                join_commit_key_hash,
                1_000,
            )?,
        ),
        (
            "origin",
            join_commit_body.clone(),
            mls_commit_federated_proof(
                &owner,
                "https://tampered.invalid",
                1,
                scope,
                &join_commit_path,
                join_submission,
                join_commit_request_digest,
                join_commit_key_hash,
                1_000,
            )?,
        ),
        (
            "action",
            join_commit_body.clone(),
            mls_commit_federated_proof(
                &owner,
                &candidate_origin,
                2,
                scope,
                &join_commit_path,
                join_submission,
                join_commit_request_digest,
                join_commit_key_hash,
                1_000,
            )?,
        ),
    ] {
        let rejected = send_federated_mls_commit(
            app.clone(),
            &join_commit_path,
            join_commit_key,
            &candidate_origin,
            proof,
            body,
        )
        .await?;
        assert_eq!(
            rejected.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "signed {label} mismatch must fail closed"
        );
    }

    let mixed_authorization = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&join_commit_path)
                .header(header::CONTENT_TYPE, MLS_COMMIT_V3_CONTENT_TYPE)
                .header("idempotency-key", join_commit_key)
                .header(IDENTITY_ORIGIN_HEADER, &candidate_origin)
                .header(MLS_COMMIT_PROOF_HEADER, valid_submit_proof.clone())
                .header(
                    header::AUTHORIZATION,
                    device_session_authorization(owner.session_id, owner.session_secret),
                )
                .body(Body::from(join_commit_body.clone()))?,
        )
        .await?;
    assert_eq!(
        mixed_authorization.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let committed = send_federated_mls_commit(
        app.clone(),
        &join_commit_path,
        join_commit_key,
        &candidate_origin,
        valid_submit_proof,
        join_commit_body.clone(),
    )
    .await?;
    assert_eq!(committed.status(), StatusCode::CREATED);
    assert_content_type(&committed, MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE);
    let committed_receipt = response_bytes(committed).await?;
    let committed_replay = send_federated_mls_commit(
        app.clone(),
        &join_commit_path,
        join_commit_key,
        &candidate_origin,
        mls_commit_federated_proof(
            &owner,
            &candidate_origin,
            1,
            scope,
            &join_commit_path,
            join_submission,
            join_commit_request_digest,
            join_commit_key_hash,
            1_500,
        )?,
        join_commit_body,
    )
    .await?;
    assert_eq!(committed_replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(committed_replay).await?, committed_receipt);

    let readback = send_federated_mls_receipt_query(
        app.clone(),
        &join_commit_path,
        &candidate_origin,
        mls_commit_federated_proof(
            &owner,
            &candidate_origin,
            2,
            scope,
            &join_commit_path,
            join_submission,
            join_commit_request_digest,
            join_commit_key_hash,
            1_600,
        )?,
    )
    .await?;
    assert_eq!(readback.status(), StatusCode::OK);
    assert_content_type(&readback, MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE);
    assert_eq!(response_bytes(readback).await?, committed_receipt);

    let (receipt_digest, committed_head) = mls_receipt_facts(&committed_receipt)?;
    let confirmation_path = format!("{join_commit_path}/confirmations/{}", candidate.device_id);
    let confirmation_body =
        mls_confirmation_body(&candidate, join_submission, receipt_digest, committed_head)?;
    let first_confirmation = send_federated_confirmation(
        app.clone(),
        &confirmation_path,
        &candidate_origin,
        mls_confirmation_proof(
            &candidate,
            &candidate_origin,
            scope,
            &confirmation_path,
            join_submission,
            &confirmation_body,
            1_000,
        )?,
        confirmation_body.clone(),
    )
    .await?;
    assert_eq!(first_confirmation.status(), StatusCode::NO_CONTENT);
    let response_loss_replay = send_federated_confirmation(
        app.clone(),
        &confirmation_path,
        &candidate_origin,
        mls_confirmation_proof(
            &candidate,
            &candidate_origin,
            scope,
            &confirmation_path,
            join_submission,
            &confirmation_body,
            1_500,
        )?,
        confirmation_body.clone(),
    )
    .await?;
    assert_eq!(response_loss_replay.status(), StatusCode::NO_CONTENT);
    let confirmation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM groups.mls_join_confirmations
          WHERE tenant_id::text=$1 AND submission_id::text=$2",
    )
    .bind(tenant_id.to_string())
    .bind(join_submission.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(
        confirmation_count, 1,
        "fresh-proof replay must keep one leaf"
    );

    // Sequencer acceptance and the GM1 member/outbox resolution commit together.
    let receipt_path = GROUP_MEMBERSHIP_RECEIPT_PATH_TEMPLATE
        .replace("{scope_kind}", "private-conversation")
        .replace(
            "{scope_id}",
            scope_path.rsplit('/').next().ok_or("scope id")?,
        )
        .replace("{membership_command_id}", &approval_command_id.to_string());
    let receipt = send_get(app.clone(), &receipt_path, &candidate).await?;
    assert_eq!(receipt.status(), StatusCode::OK);
    assert_membership_phase(&response_bytes(receipt).await?, 4)?;

    revoke_device(&identity_store, &candidate, 30_000).await?;
    let revoked_confirmation = send_federated_confirmation(
        app.clone(),
        &confirmation_path,
        &candidate_origin,
        mls_confirmation_proof(
            &candidate,
            &candidate_origin,
            scope,
            &confirmation_path,
            join_submission,
            &confirmation_body,
            1_800,
        )?,
        confirmation_body,
    )
    .await?;
    assert_eq!(revoked_confirmation.status(), StatusCode::UNAUTHORIZED);
    identity_server.abort();
    Ok(())
}
