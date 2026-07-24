#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn remote_owner_admin_and_candidate_use_fresh_identity_logs_without_session_forwarding()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let group_store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let owner = enroll_active_device(&identity_store, 51, 52, 53, [54; 32]).await?;
    let admin = enroll_active_device(&identity_store, 61, 62, 63, [64; 32]).await?;
    let candidate = enroll_active_device(&identity_store, 71, 72, 73, [74; 32]).await?;
    let (admin_origin, admin_server) = start_identity_log_server(identity_store.clone()).await?;
    let (candidate_origin, candidate_server) =
        start_identity_log_server(identity_store.clone()).await?;
    let tenant_id = TenantId::new();
    let state =
        GroupNodeState::with_clock(group_store.clone(), tenant_id, Arc::new(FixedClock(NOW)))
            .with_public_origin_and_allowed_http_identity_origins(
                AUDIENCE,
                [admin_origin.clone(), candidate_origin.clone()],
            )?;
    let app = group_router_with_state(state);
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let create_key = "federated-group-create-0001";
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

    let grant_path = format!("{scope_path}/admins/{}", admin.identity_id);
    let grant_key = "federated-grant-admin-0001";
    let grant = send_mutation(
        app.clone(),
        "PUT",
        &grant_path,
        "application/vnd.dirextalk.group-grant-admin.v1+cbor",
        grant_key,
        &owner,
        grant_admin_body(
            &owner,
            scope,
            &grant_path,
            grant_key,
            1_000,
            Revision::INITIAL,
            admin.identity_id,
        )?,
    )
    .await?;
    assert_eq!(grant.status(), StatusCode::CREATED);

    let invite_id = InviteCapabilityId::new();
    let invite_path = format!("{scope_path}/invites/{invite_id}");
    let invite_key = "federated-admin-invite-0001";
    let invite_body = federated_issue_invite_body(
        &admin,
        &admin_origin,
        scope,
        &invite_path,
        invite_key,
        1_000,
        Revision::new(2)?,
        Some(candidate.identity_id),
        1,
        10_000,
    )?;
    let invite = send_federated_mutation(
        app.clone(),
        "PUT",
        &invite_path,
        GROUP_ISSUE_INVITE_CONTENT_TYPE,
        invite_key,
        &admin_origin,
        invite_body,
    )
    .await?;
    assert_eq!(invite.status(), StatusCode::CREATED);

    let join_request_id = JoinRequestId::new();
    let join_command_id = RequestId::new();
    let join_path = format!("{scope_path}/join-requests/{join_request_id}");
    let join_key = "federated-candidate-join-0001";
    let join_body = federated_join_request_body(
        &candidate,
        &candidate_origin,
        scope,
        &join_path,
        join_key,
        1_000,
        join_command_id,
        invite_id,
        Revision::new(3)?,
        Sha256Digest::hash_domain(b"test-group-head\0", b"federated-join"),
    )?;
    let join = send_federated_mutation(
        app.clone(),
        "PUT",
        &join_path,
        GROUP_JOIN_REQUEST_CONTENT_TYPE,
        join_key,
        &candidate_origin,
        join_body.clone(),
    )
    .await?;
    assert_eq!(join.status(), StatusCode::ACCEPTED);
    assert_membership_phase(&response_bytes(join).await?, 1)?;
    let join_receipt_path = format!("{scope_path}/membership-receipts/{join_command_id}");
    let recovered_join = send_federated_get(
        app.clone(),
        &join_receipt_path,
        &candidate_origin,
        receipt_query_proof(
            &candidate,
            &candidate_origin,
            scope,
            &join_receipt_path,
            join_command_id,
            1_500,
        )?,
    )
    .await?;
    assert_eq!(recovered_join.status(), StatusCode::OK);
    assert_membership_phase(&response_bytes(recovered_join).await?, 1)?;

    let approval_path = format!("{join_path}/approvals");
    let approval_key = "federated-admin-approval-0001";
    let approval = send_federated_mutation(
        app.clone(),
        "POST",
        &approval_path,
        GROUP_APPROVE_JOIN_CONTENT_TYPE,
        approval_key,
        &admin_origin,
        federated_approve_join_body(
            &admin,
            &admin_origin,
            scope,
            &approval_path,
            approval_key,
            1_000,
            RequestId::new(),
            candidate.identity_id,
            candidate.device_id,
            invite_id,
            Revision::new(4)?,
            Sha256Digest::hash_domain(b"test-group-head\0", b"federated-approval"),
        )?,
    )
    .await?;
    assert_eq!(approval.status(), StatusCode::ACCEPTED);
    assert_membership_phase(&response_bytes(approval).await?, 2)?;

    revoke_device(&identity_store, &candidate, 30_000).await?;
    let revoked_replay = send_federated_mutation(
        app,
        "PUT",
        &join_path,
        GROUP_JOIN_REQUEST_CONTENT_TYPE,
        join_key,
        &candidate_origin,
        join_body,
    )
    .await?;
    assert_eq!(revoked_replay.status(), StatusCode::UNAUTHORIZED);

    admin_server.abort();
    candidate_server.abort();
    Ok(())
}
