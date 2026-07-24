#[tokio::test]
#[ignore = "requires the disposable three-node Docker Compose cluster"]
#[allow(clippy::too_many_lines)]
async fn three_node_compose_runs_v30_peer_admission_and_exact_recovery_over_tls()
-> Result<(), Box<dyn Error>> {
    if std::env::var("DTX_THREE_NODE_COMPOSE_ACCEPTANCE").as_deref() != Ok("1") {
        return Err(
            "set DTX_THREE_NODE_COMPOSE_ACCEPTANCE=1 for the disposable local cluster".into(),
        );
    }

    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let postgres_port = std::env::var("DTX_THREE_NODE_POSTGRES_PORT")
        .unwrap_or_else(|_| "15432".to_owned())
        .parse::<u16>()?;
    let admin_a = sqlx::PgPool::connect(&format!(
        "postgres://postgres@127.0.0.1:{postgres_port}/dtx_node_a?sslmode=disable"
    ))
    .await?;
    let admin_b = sqlx::PgPool::connect(&format!(
        "postgres://postgres@127.0.0.1:{postgres_port}/dtx_node_b?sslmode=disable"
    ))
    .await?;
    let admin_c = sqlx::PgPool::connect(&format!(
        "postgres://postgres@127.0.0.1:{postgres_port}/dtx_node_c?sslmode=disable"
    ))
    .await?;
    for (node, pool) in [("A", &admin_a), ("B", &admin_b), ("C", &admin_c)] {
        let migration_026_applied: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM public._sqlx_migrations
                  WHERE version=202607160026 AND success)",
        )
        .fetch_one(pool)
        .await?;
        assert!(
            migration_026_applied,
            "node {node} must apply migration 026"
        );
    }

    let identity_a = IdentityPgStore::connect(
        PgConnectOptions::from_str(&format!(
            "postgres://dtx_identity_node@127.0.0.1:{postgres_port}/dtx_node_a?sslmode=disable"
        ))?,
        2,
    )
    .await?;
    let identity_b = IdentityPgStore::connect(
        PgConnectOptions::from_str(&format!(
            "postgres://dtx_identity_node@127.0.0.1:{postgres_port}/dtx_node_b?sslmode=disable"
        ))?,
        2,
    )
    .await?;
    let owner = enroll_active_device_at(&identity_a, 151, 152, 153, [154; 32], now).await?;
    let candidate = enroll_active_device_at(&identity_b, 161, 162, 163, [164; 32], now).await?;

    let ca_file = std::env::var("DTX_THREE_NODE_TLS_CA_FILE").map_err(|_| {
        "set DTX_THREE_NODE_TLS_CA_FILE to the local Compose CA emitted by scripts/local-cluster.ps1"
    })?;
    let local_test_ca = reqwest::Certificate::from_pem(&std::fs::read(ca_file)?)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .add_root_certificate(local_test_ca)
        .resolve("node-a", "127.0.0.1:18443".parse::<SocketAddr>()?)
        .resolve("node-b", "127.0.0.1:18444".parse::<SocketAddr>()?)
        .resolve("node-c", "127.0.0.1:18445".parse::<SocketAddr>()?)
        .build()?;
    for (host, port, expected_origin) in [
        ("node-a", 18_443, "https://node-a:8443"),
        ("node-b", 18_444, "https://node-b:8443"),
        ("node-c", 18_445, "https://node-c:8443"),
    ] {
        let health = client
            .get(format!("https://{host}:{port}/local/live"))
            .send()
            .await?;
        assert_eq!(health.status(), StatusCode::NO_CONTENT);
        let response = client
            .get(format!(
                "https://{host}:{port}{GROUP_SERVICE_DESCRIPTOR_PATH}"
            ))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE)
        );
        let CanonicalValue::Map(descriptor) = decode_deterministic_cbor(&response.bytes().await?)?
        else {
            return Err("unified Group Service descriptor must be a map".into());
        };
        assert_eq!(
            descriptor[1].1,
            CanonicalValue::Text(expected_origin.to_owned())
        );
        assert!(matches!(
            &descriptor[5].1,
            CanonicalValue::Bytes(key) if key.len() == 32
        ));
        assert_eq!(descriptor[3].1, CanonicalValue::Unsigned(5));
        assert_eq!(descriptor[4].1, CanonicalValue::Unsigned(64));
    }
    let group_origin = "https://node-a:18443";
    let candidate_identity_origin = "https://node-b:8443";
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);

    let create_key = "compose-federated-create-0001";
    let create = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::PUT,
        &scope_path,
        GROUP_CREATE_CONTENT_TYPE,
        create_key,
        Some(device_session_authorization(
            owner.session_id,
            owner.session_secret,
        )),
        None,
        create_body(&owner, scope, &scope_path, create_key, now)?,
    )
    .await?;
    assert_eq!(create.status(), StatusCode::CREATED);

    let bootstrap_submission = RequestId::new();
    let bootstrap_path = format!("{scope_path}/mls-commits/{bootstrap_submission}");
    let bootstrap_key = "compose-v30-owner-bootstrap-0001";
    let bootstrap = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::POST,
        &bootstrap_path,
        MLS_COMMIT_CONTENT_TYPE,
        bootstrap_key,
        Some(device_session_authorization(
            owner.session_id,
            owner.session_secret,
        )),
        None,
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
    assert_eq!(
        bootstrap
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(MLS_COMMIT_RECEIPT_CONTENT_TYPE)
    );
    let bootstrap_head = mls_receipt_head(&bootstrap.bytes().await?)?;

    let invite_id = InviteCapabilityId::new();
    let invite_path = format!("{scope_path}/invites/{invite_id}");
    let invite_key = "compose-federated-invite-0001";
    let invite = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::PUT,
        &invite_path,
        GROUP_ISSUE_INVITE_CONTENT_TYPE,
        invite_key,
        Some(device_session_authorization(
            owner.session_id,
            owner.session_secret,
        )),
        None,
        issue_invite_body(
            &owner,
            scope,
            &invite_path,
            invite_key,
            now,
            Revision::INITIAL,
            Some(candidate.identity_id),
            1,
            now + 600_000,
        )?,
    )
    .await?;
    assert_eq!(invite.status(), StatusCode::CREATED);

    let join_request_id = JoinRequestId::new();
    let join_command_id = RequestId::new();
    let join_path = format!("{scope_path}/join-requests/{join_request_id}");
    let join_key = "compose-v30-federated-join-0001";
    let candidate_key_package_digest = test_candidate_key_package_digest(&candidate);
    let join = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::PUT,
        &join_path,
        GROUP_JOIN_REQUEST_V2_CONTENT_TYPE,
        join_key,
        None,
        Some(candidate_identity_origin),
        federated_join_request_body_v2(
            &candidate,
            candidate_identity_origin,
            scope,
            &join_path,
            join_key,
            now,
            join_command_id,
            invite_id,
            Revision::new(2)?,
            bootstrap_head,
            candidate_key_package_digest,
        )?,
    )
    .await?;
    assert_eq!(join.status(), StatusCode::ACCEPTED);
    assert_eq!(
        join.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE)
    );
    let join_receipt = join.bytes().await?;
    assert_membership_phase(&join_receipt, 1)?;
    let join_request_digest = membership_receipt_request_digest(&join_receipt)?;

    let approval_command_id = RequestId::new();
    let approval_path = format!("{join_path}/approvals");
    let approval_key = "compose-v30-owner-approval-0001";
    let approval_body = approve_join_body_v2(
        &owner,
        scope,
        &approval_path,
        approval_key,
        now,
        approval_command_id,
        candidate.identity_id,
        candidate.device_id,
        invite_id,
        Revision::new(3)?,
        bootstrap_head,
        candidate_key_package_digest,
    )?;
    let authorization_digest = action_proof_binding_digest(&approval_body)?;
    let approval = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::POST,
        &approval_path,
        GROUP_APPROVE_JOIN_V2_CONTENT_TYPE,
        approval_key,
        Some(device_session_authorization(
            owner.session_id,
            owner.session_secret,
        )),
        None,
        approval_body,
    )
    .await?;
    assert_eq!(approval.status(), StatusCode::ACCEPTED);
    assert_eq!(
        approval
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE)
    );
    let approval_receipt = approval.bytes().await?;
    assert_membership_phase(&approval_receipt, 2)?;
    let approval_request_digest = membership_receipt_request_digest(&approval_receipt)?;

    let join_submission = RequestId::new();
    let join_commit_path = format!("{scope_path}/mls-commits/{join_submission}");
    let join_commit_key = "compose-v30-approved-join-0001";
    let join_commit_body = mls_commit_body_v3(
        &owner,
        &candidate,
        scope,
        join_submission,
        1,
        bootstrap_head,
        vec![0x52; 48],
        dtx_membership_command::MembershipCommandId::new(approval_command_id),
        authorization_digest,
        join_request_digest,
        approval_request_digest,
        candidate_key_package_digest,
    )?;
    let committed = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::POST,
        &join_commit_path,
        MLS_COMMIT_V3_CONTENT_TYPE,
        join_commit_key,
        Some(device_session_authorization(
            owner.session_id,
            owner.session_secret,
        )),
        None,
        join_commit_body.clone(),
    )
    .await?;
    assert_eq!(committed.status(), StatusCode::CREATED);
    assert_eq!(
        committed
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE)
    );
    let committed_receipt = committed.bytes().await?.to_vec();

    // Model a lost POST response after GM1 has already committed. The exact
    // replay must converge to the original signed receipt, not an expired
    // invite or missing-application error.
    let recovered_commit = send_network_mutation(
        &client,
        group_origin,
        reqwest::Method::POST,
        &join_commit_path,
        MLS_COMMIT_V3_CONTENT_TYPE,
        join_commit_key,
        Some(device_session_authorization(
            owner.session_id,
            owner.session_secret,
        )),
        None,
        join_commit_body,
    )
    .await?;
    assert_eq!(recovered_commit.status(), StatusCode::OK);
    assert_eq!(recovered_commit.bytes().await?.as_ref(), committed_receipt);

    let (receipt_digest, committed_head) = mls_receipt_facts(&committed_receipt)?;
    let confirmation_path = format!("{join_commit_path}/confirmations/{}", candidate.device_id);
    let confirmation_body =
        mls_confirmation_body(&candidate, join_submission, receipt_digest, committed_head)?;
    let first_confirmation = send_network_federated_confirmation(
        &client,
        group_origin,
        &confirmation_path,
        candidate_identity_origin,
        mls_confirmation_proof(
            &candidate,
            candidate_identity_origin,
            scope,
            &confirmation_path,
            join_submission,
            &confirmation_body,
            now + 3,
        )?,
        confirmation_body.clone(),
    )
    .await?;
    assert_eq!(first_confirmation.status(), StatusCode::NO_CONTENT);
    let recovered_confirmation = send_network_federated_confirmation(
        &client,
        group_origin,
        &confirmation_path,
        candidate_identity_origin,
        mls_confirmation_proof(
            &candidate,
            candidate_identity_origin,
            scope,
            &confirmation_path,
            join_submission,
            &confirmation_body,
            now + 4,
        )?,
        confirmation_body,
    )
    .await?;
    assert_eq!(recovered_confirmation.status(), StatusCode::NO_CONTENT);
    let confirmation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM groups.mls_join_confirmations WHERE submission_id::text=$1",
    )
    .bind(join_submission.to_string())
    .fetch_one(&admin_a)
    .await?;
    assert_eq!(confirmation_count, 1, "fresh-proof replay keeps one leaf");

    let approval_receipt_path = format!("{scope_path}/membership-receipts/{approval_command_id}");
    let committed_membership = send_network_receipt_query(
        &client,
        group_origin,
        &approval_receipt_path,
        candidate_identity_origin,
        receipt_query_proof(
            &candidate,
            candidate_identity_origin,
            scope,
            &approval_receipt_path,
            approval_command_id,
            now + 5,
        )?,
    )
    .await?;
    assert_eq!(committed_membership.status(), StatusCode::OK);
    assert_membership_phase(&committed_membership.bytes().await?, 4)?;

    let scope_id = scope_path.rsplit('/').next().ok_or("scope ID")?;
    for (node, pool, expected) in [
        ("A", &admin_a, 1_i64),
        ("B", &admin_b, 0_i64),
        ("C", &admin_c, 0_i64),
    ] {
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM groups.policy_heads WHERE scope_id=$1")
                .bind(scope_id)
                .fetch_one(pool)
                .await?;
        assert_eq!(count, expected, "group scope isolation on node {node}");
    }
    Ok(())
}
