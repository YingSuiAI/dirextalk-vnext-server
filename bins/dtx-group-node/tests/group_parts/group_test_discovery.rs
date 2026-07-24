#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn owner_admin_discovery_is_bound_paged_cached_and_restart_safe() -> Result<(), Box<dyn Error>>
{
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let group_store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let untrusted_http_public_origin = "http://group.test";
    assert!(
        GroupNodeState::with_clock(
            group_store.clone(),
            TenantId::new(),
            Arc::new(FixedClock(NOW)),
        )
        .with_public_origin_and_allowed_http_identity_origins(untrusted_http_public_origin, [])
        .is_err()
    );
    assert!(
        GroupNodeState::with_clock(
            group_store.clone(),
            TenantId::new(),
            Arc::new(FixedClock(NOW)),
        )
        .with_public_origin_and_allowed_http_identity_origins(
            untrusted_http_public_origin,
            ["http://other.test".to_owned()],
        )
        .is_err()
    );
    assert!(
        GroupNodeState::with_clock(
            group_store.clone(),
            TenantId::new(),
            Arc::new(FixedClock(NOW)),
        )
        .with_public_origin_and_allowed_http_identity_origins(
            untrusted_http_public_origin,
            [untrusted_http_public_origin.to_owned()],
        )
        .is_ok()
    );
    let owner = enroll_active_device(&identity_store, 81, 82, 83, [84; 32]).await?;
    let remote_admin = enroll_active_device(&identity_store, 85, 86, 87, [88; 32]).await?;
    let local_candidate = enroll_active_device(&identity_store, 89, 90, 91, [92; 32]).await?;
    let remote_candidate = enroll_active_device(&identity_store, 93, 94, 95, [96; 32]).await?;
    let ordinary_member = enroll_active_device(&identity_store, 97, 98, 99, [100; 32]).await?;
    let (remote_origin, identity_server) = start_identity_log_server(identity_store).await?;
    let tenant_id = TenantId::new();
    let sequencer_key = SigningKey::from_bytes(&[101; 32]);
    let build_state = || {
        GroupNodeState::with_clock(group_store.clone(), tenant_id, Arc::new(FixedClock(NOW)))
            .with_mls_sequencer_signing_key(sequencer_key.clone())
            .with_public_origin_and_allowed_http_identity_origins(AUDIENCE, [remote_origin.clone()])
    };
    let app = group_router_with_state(build_state()?);
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let descriptor = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(GROUP_SERVICE_DESCRIPTOR_PATH)
                .header(header::HOST, "attacker.invalid")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(descriptor.status(), StatusCode::OK);
    assert_content_type(&descriptor, GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE);
    assert_eq!(
        descriptor
            .headers()
            .get(header::CACHE_CONTROL)
            .ok_or("descriptor cache policy")?,
        "public, max-age=60, stale-while-revalidate=300"
    );
    let descriptor_etag = descriptor
        .headers()
        .get(header::ETAG)
        .ok_or("descriptor ETag")?
        .clone();
    let descriptor_value = decode_deterministic_cbor(&response_bytes(descriptor).await?)?;
    let CanonicalValue::Map(descriptor_fields) = descriptor_value else {
        return Err("descriptor must be a canonical map".into());
    };
    assert_eq!(
        descriptor_fields[1].1,
        CanonicalValue::Text(AUDIENCE.to_owned())
    );
    let not_modified = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(GROUP_SERVICE_DESCRIPTOR_PATH)
                .header(header::HOST, "different.invalid")
                .header(header::IF_NONE_MATCH, descriptor_etag)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

    let create_key = "discovery-create-0001";
    assert_eq!(
        send_mutation(
            app.clone(),
            "PUT",
            &scope_path,
            GROUP_CREATE_CONTENT_TYPE,
            create_key,
            &owner,
            create_body(&owner, scope, &scope_path, create_key, 1_000)?,
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    let grant_path = format!("{scope_path}/admins/{}", remote_admin.identity_id);
    let grant_key = "discovery-grant-admin-0001";
    assert_eq!(
        send_mutation(
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
                remote_admin.identity_id,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED
    );

    let local_invite = InviteCapabilityId::new();
    let local_invite_path = format!("{scope_path}/invites/{local_invite}");
    let local_invite_key = "discovery-local-invite-0001";
    assert_eq!(
        send_mutation(
            app.clone(),
            "PUT",
            &local_invite_path,
            GROUP_ISSUE_INVITE_CONTENT_TYPE,
            local_invite_key,
            &owner,
            issue_invite_body(
                &owner,
                scope,
                &local_invite_path,
                local_invite_key,
                1_000,
                Revision::new(2)?,
                Some(local_candidate.identity_id),
                1,
                10_000,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    let local_join_id = JoinRequestId::new();
    let local_join_path = format!("{scope_path}/join-requests/{local_join_id}");
    let local_join_key = "discovery-local-join-0001";
    assert_eq!(
        send_mutation(
            app.clone(),
            "PUT",
            &local_join_path,
            GROUP_JOIN_REQUEST_CONTENT_TYPE,
            local_join_key,
            &local_candidate,
            join_request_body(
                &local_candidate,
                scope,
                &local_join_path,
                local_join_key,
                1_000,
                RequestId::new(),
                local_invite,
                Revision::new(3)?,
                Sha256Digest::hash_domain(b"test-group-head\0", b"discovery-local"),
            )?,
        )
        .await?
        .status(),
        StatusCode::ACCEPTED
    );

    let remote_invite = InviteCapabilityId::new();
    let remote_invite_path = format!("{scope_path}/invites/{remote_invite}");
    let remote_invite_key = "discovery-remote-invite-0001";
    assert_eq!(
        send_mutation(
            app.clone(),
            "PUT",
            &remote_invite_path,
            GROUP_ISSUE_INVITE_CONTENT_TYPE,
            remote_invite_key,
            &owner,
            issue_invite_body(
                &owner,
                scope,
                &remote_invite_path,
                remote_invite_key,
                1_000,
                Revision::new(4)?,
                Some(remote_candidate.identity_id),
                1,
                10_000,
            )?,
        )
        .await?
        .status(),
        StatusCode::CREATED
    );
    let remote_join_id = JoinRequestId::new();
    let remote_join_path = format!("{scope_path}/join-requests/{remote_join_id}");
    let remote_join_key = "discovery-remote-join-0001";
    assert_eq!(
        send_federated_mutation(
            app.clone(),
            "PUT",
            &remote_join_path,
            GROUP_JOIN_REQUEST_CONTENT_TYPE,
            remote_join_key,
            &remote_origin,
            federated_join_request_body(
                &remote_candidate,
                &remote_origin,
                scope,
                &remote_join_path,
                remote_join_key,
                1_000,
                RequestId::new(),
                remote_invite,
                Revision::new(5)?,
                Sha256Digest::hash_domain(b"test-group-head\0", b"discovery-remote"),
            )?,
        )
        .await?
        .status(),
        StatusCode::ACCEPTED
    );

    let first_target = format!("{scope_path}/join-requests?after=&limit=1");
    let wrong_join_action = send_group_query(
        app.clone(),
        &first_target,
        &remote_admin,
        &remote_origin,
        true,
        group_query_proof_for_action(
            &remote_admin,
            &remote_origin,
            scope,
            &first_target,
            2,
            1_000,
        )?,
    )
    .await?;
    assert_eq!(wrong_join_action.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let first = send_group_query(
        app.clone(),
        &first_target,
        &remote_admin,
        &remote_origin,
        true,
        group_query_proof(&remote_admin, &remote_origin, scope, &first_target, 1_000)?,
    )
    .await?;
    assert_eq!(first.status(), StatusCode::OK);
    assert_content_type(&first, GROUP_JOIN_REQUEST_PAGE_CONTENT_TYPE);
    let (mut discovered, next_after) = decode_discovery_page(&response_bytes(first).await?)?;
    let next_after = next_after.ok_or("first discovery page must continue")?;

    let tampered_target = format!("{scope_path}/join-requests?after=&limit=2");
    let tampered = send_group_query(
        app.clone(),
        &tampered_target,
        &remote_admin,
        &remote_origin,
        true,
        group_query_proof(&remote_admin, &remote_origin, scope, &first_target, 1_000)?,
    )
    .await?;
    assert_eq!(tampered.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let second_target = format!("{scope_path}/join-requests?after={next_after}&limit=1");
    let second = send_group_query(
        app.clone(),
        &second_target,
        &remote_admin,
        &remote_origin,
        true,
        group_query_proof(&remote_admin, &remote_origin, scope, &second_target, 1_100)?,
    )
    .await?;
    let (second_items, second_next) = decode_discovery_page(&response_bytes(second).await?)?;
    assert!(second_next.is_none());
    discovered.extend(second_items);
    discovered.sort();
    let mut expected = vec![
        (local_join_id.to_string(), AUDIENCE.to_owned()),
        (remote_join_id.to_string(), remote_origin.clone()),
    ];
    expected.sort();
    assert_eq!(discovered, expected);

    let restarted = group_router_with_state(build_state()?);
    let restart_target = format!("{scope_path}/join-requests?after=&limit=64");
    let restart_page = send_group_query(
        restarted.clone(),
        &restart_target,
        &owner,
        AUDIENCE,
        false,
        group_query_proof(&owner, AUDIENCE, scope, &restart_target, 1_200)?,
    )
    .await?;
    assert_eq!(restart_page.status(), StatusCode::OK);
    assert_eq!(
        decode_discovery_page(&response_bytes(restart_page).await?)?
            .0
            .len(),
        2
    );

    let scope_id = scope_path.rsplit('/').next().ok_or("scope id")?;
    let persisted_origins: Vec<String> = sqlx::query_scalar(
        "SELECT candidate_identity_origin
           FROM groups.membership_workflows
          WHERE tenant_id=$1 AND scope_kind='private_conversation' AND scope_id=$2
          ORDER BY candidate_identity_origin",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .bind(scope_id)
    .fetch_all(harness.admin_pool())
    .await?;
    let mut expected_origins = vec![AUDIENCE.to_owned(), remote_origin.clone()];
    expected_origins.sort();
    assert_eq!(persisted_origins, expected_origins);

    sqlx::query(
        "INSERT INTO groups.members
             (tenant_id, scope_kind, scope_id, identity_id, admitted_at_ms)
         VALUES ($1, 'private_conversation', $2, $3, $4)",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .bind(scope_id)
    .bind(ordinary_member.identity_id.to_string())
    .bind(NOW)
    .execute(harness.admin_pool())
    .await?;
    let member_denied = send_group_query(
        restarted.clone(),
        &restart_target,
        &ordinary_member,
        AUDIENCE,
        false,
        group_query_proof(&ordinary_member, AUDIENCE, scope, &restart_target, 1_300)?,
    )
    .await?;
    assert_eq!(member_denied.status(), StatusCode::FORBIDDEN);

    sqlx::query(
        "UPDATE groups.membership_workflows
            SET candidate_identity_origin=NULL
          WHERE tenant_id=$1 AND scope_kind='private_conversation' AND scope_id=$2
            AND request_id=$3",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .bind(scope_id)
    .bind(uuid::Uuid::from(local_join_id))
    .execute(harness.admin_pool())
    .await?;
    let historical_unavailable = send_group_query(
        restarted,
        &restart_target,
        &remote_admin,
        &remote_origin,
        true,
        group_query_proof(&remote_admin, &remote_origin, scope, &restart_target, 1_400)?,
    )
    .await?;
    assert_eq!(
        historical_unavailable.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    identity_server.abort();
    Ok(())
}
