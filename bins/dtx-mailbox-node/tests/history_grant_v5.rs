#[path = "mailbox_support.rs"]
mod common;
use common::*;

async fn send_history_testkit_request(
    app: axum::Router,
    request: history_testkit::HttpRequest,
) -> Result<history_testkit::HttpResponse, Box<dyn Error>> {
    let mut builder = Request::builder()
        .method(request.method.as_str())
        .uri(request.path);
    for (name, value) in request.headers {
        builder = builder.header(name, value);
    }
    let response = app.oneshot(builder.body(Body::from(request.body))?).await?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
        })
        .collect();
    let body = to_bytes(response.into_body(), 1_100_000).await?.to_vec();
    Ok(history_testkit::HttpResponse {
        status,
        headers,
        body,
    })
}

async fn open_history_recovery_device(
    store: &IdentityPgStore,
    owner: &ActiveDevice,
    candidate_seed: u8,
    encryption_seed: u8,
    capability_bytes: [u8; 32],
) -> Result<(ActiveDevice, DeviceEnrollmentChallengeId), Box<dyn Error>> {
    let candidate = SigningKey::from_bytes(&[candidate_seed; 32]);
    let candidate_public = public_key(&candidate)?;
    let recipient_key = DeviceEncryptionPublicKey::try_from([encryption_seed; 32])?;
    let candidate_device_id = DeviceId::new();
    let created = DeviceEnrollmentRepository
        .create_challenge(
            store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::hash_domain(
                    b"mailbox-open-history-recovery\0",
                    candidate_device_id.to_string().as_bytes(),
                ),
                owner.identity_id,
                candidate_device_id,
                candidate_public,
                recipient_key,
                DeviceEnrollmentCapability::new(capability_bytes)?,
            )?,
            UtcMillis::new(NOW + 1)?,
        )
        .await?;
    let request_id = match created {
        DeviceEnrollmentChallengeOutcome::Created(challenge)
        | DeviceEnrollmentChallengeOutcome::Replayed(challenge) => challenge.challenge_id(),
    };
    Ok((
        ActiveDevice {
            root: SigningKey::from_bytes(&owner.root.to_bytes()),
            recovery: SigningKey::from_bytes(&owner.recovery.to_bytes()),
            identity_id: owner.identity_id,
            device_id: candidate_device_id,
            session_id: DeviceSessionId::new(),
            session_secret: [0; 32],
        },
        request_id,
    ))
}

#[tokio::test]
async fn history_grant_v5_http_boundary_uses_production_parser_and_role_gate()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 2).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 2).await?;
    let app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(NOW)),
    ));
    let provider = enroll_active_device(&identity_store, 211, 212, 213, [214; 32]).await?;

    let invalid = send_v2(
        app.clone(),
        DEVICE_HISTORY_GRANT_V5_PATH,
        DEVICE_HISTORY_GRANT_V5_CONTENT_TYPE,
        Some("grant-v5-invalid-parser"),
        provider.session_id,
        provider.session_secret,
        vec![0xa0],
    )
    .await?;
    assert_eq!(invalid.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let unauthenticated = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(DEVICE_HISTORY_GRANT_V5_PATH)
                .header(header::CONTENT_TYPE, DEVICE_HISTORY_GRANT_V5_CONTENT_TYPE)
                .header("idempotency-key", "grant-v5-unauthenticated")
                .body(Body::from(vec![0xa0]))?,
        )
        .await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn history_grant_v5_http_success_replays_exactly_and_rejects_mismatch()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let mut privilege_probe =
        PgConnection::connect_with(&harness.mailbox_runtime_options()).await?;
    let (identity_select, identity_update): (bool, bool) = sqlx::query_as(
        "SELECT bool_and(has_table_privilege(current_user, table_name, 'SELECT')),\n                bool_or(has_table_privilege(current_user, table_name, 'UPDATE'))\n           FROM unnest(ARRAY['identity.history_recovery_requests',\n                             'identity.device_enrollment_challenges',\n                             'identity.recovery_scope_catalogs',\n                             'identity.recovery_scope_catalog_preparations']::text[]) AS tables(table_name)",
    )
    .fetch_one(&mut privilege_probe)
    .await?;
    assert!(
        identity_select,
        "mailbox runtime must retain identity evidence SELECT"
    );
    assert!(
        !identity_update,
        "mailbox runtime identity evidence must remain SELECT-only"
    );
    let identity_app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            identity_store.clone(),
            Arc::new(FixedClock(10_000)),
            AUDIENCE,
        ),
    );
    let mailbox_app = mailbox_router_with_state(MailboxNodeState::with_clock(
        mailbox_store,
        Arc::new(FixedClock(10_000)),
    ));

    let owner = enroll_active_device(&identity_store, 211, 212, 213, [214; 32]).await?;
    let provider = add_active_device(&identity_store, &owner, 215, [216; 32]).await?;
    let observed_head = IdentityLogRepository::new()
        .load(&identity_store, owner.identity_id)
        .await?
        .ok_or("identity head missing before recovery request")?
        .head();
    let owner_device_signer = SigningKey::from_bytes(&[213; 32]);
    let catalog_id = Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b1")?;
    let authority_key_id = Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b2")?;
    let catalog = history_testkit::catalog_v2(
        owner.identity_id,
        catalog_id,
        1,
        None,
        observed_head.sequence().get(),
        *observed_head.hash().as_bytes(),
        owner.device_id,
        authority_key_id,
        &owner_device_signer,
        [31; 32],
        b"opaque-encrypted-catalog-v2",
        2_500,
        250_000,
    );
    let catalog_path = RECOVERY_SCOPE_CATALOG_PATH_TEMPLATE
        .replace("{catalog_id}", &catalog_id.to_string())
        .replace("{generation}", "1");
    let catalog_request = history_testkit::HttpRequest::new("PUT", catalog_path, catalog.clone())
        .header("content-type", RECOVERY_SCOPE_CATALOG_CONTENT_TYPE)
        .header("accept", RECOVERY_SCOPE_CATALOG_HEAD_CONTENT_TYPE)
        .header("idempotency-key", "mailbox-catalog-0001")
        .header(
            "authorization",
            device_session_authorization(owner.session_id, owner.session_secret),
        );
    let catalog_response = history_testkit::run_http_workflow(
        [history_testkit::HttpStep::new("catalog", catalog_request)],
        |request| send_history_testkit_request(identity_app.clone(), request),
    )
    .await
    .map_err(|error| format!("{}: {}", error.step, error.source))?
    .pop()
    .ok_or("catalog response missing")?;
    assert!(
        matches!(catalog_response.status, 200 | 201),
        "catalog status {} code {:?}",
        catalog_response.status,
        serde_json::from_slice::<serde_json::Value>(&catalog_response.body)
            .ok()
            .and_then(|v| v
                .pointer("/error/code")
                .and_then(|v| v.as_str())
                .map(str::to_owned))
    );
    let catalog_head = catalog_response.body;
    let catalog_head_digest = Sha256Digest::hash_domain(
        dtx_identity_persistence::CATALOG_HEAD_DIGEST_DOMAIN,
        &catalog_head,
    );
    let capability = [220; 32];
    let (recovered_active, request_id) =
        open_history_recovery_device(&identity_store, &owner, 217, 218, capability).await?;
    let candidate = SigningKey::from_bytes(&[217; 32]);
    let candidate_device_add = device_add(
        &owner.root,
        &candidate,
        owner.identity_id,
        recovered_active.device_id,
        218,
        observed_head.hash(),
        observed_head.sequence().get() + 1,
        NOW + 2,
    )?
    .to_deterministic_cbor()?;
    let mut recovered = RecoveredDevice {
        active: recovered_active,
        request_id,
        request_digest: Sha256Digest::from_bytes([0; 32]),
        approved_head: observed_head,
        recipient_package_digest: Sha256Digest::hash_domain(
            b"dirextalk.history-recovery-recipient-package.v1\0",
            &[218; 32],
        ),
    };
    let provider_signer = SigningKey::from_bytes(&[215; 32]);
    let response_capability = [221; 32];
    let preparation = history_testkit::preparation_v2(
        recovered.request_id,
        owner.identity_id,
        recovered.active.device_id,
        &candidate,
        [218; 32],
        observed_head.sequence().get(),
        *observed_head.hash().as_bytes(),
        response_capability,
        catalog_id,
        1,
        *catalog_head_digest.as_bytes(),
        "mailbox-preparation-0001",
        3_000,
        200_000,
    );
    let preparation_request = history_testkit::HttpRequest::new(
        "POST",
        RECOVERY_SCOPE_CATALOG_PREPARATIONS_PATH,
        preparation.clone(),
    )
    .header(
        "content-type",
        RECOVERY_SCOPE_CATALOG_PREPARATION_CONTENT_TYPE,
    )
    .header(
        "accept",
        RECOVERY_SCOPE_CATALOG_PREPARATION_RECEIPT_CONTENT_TYPE,
    )
    .header("idempotency-key", "mailbox-preparation-0001")
    .header(
        DEVICE_ENROLLMENT_CAPABILITY_HEADER,
        Base64UrlUnpadded::encode_string(&capability),
    )
    .header(
        RECOVERY_RESPONSE_CAPABILITY_HEADER,
        Base64UrlUnpadded::encode_string(&response_capability),
    );
    let preparation_response =
        send_history_testkit_request(identity_app.clone(), preparation_request).await?;
    assert!(
        matches!(preparation_response.status, 200 | 201),
        "preparation status {} code {:?}",
        preparation_response.status,
        serde_json::from_slice::<serde_json::Value>(&preparation_response.body)
            .ok()
            .and_then(|v| v
                .pointer("/error/code")
                .and_then(|v| v.as_str())
                .map(str::to_owned))
    );
    recovered.approved_head = match DeviceEnrollmentRepository
        .approve(
            &identity_store,
            DeviceEnrollmentApprovalCommand::new(
                Sha256Digest::hash_domain(
                    b"mailbox-open-history-approval\0",
                    request_id.to_string().as_bytes(),
                ),
                request_id,
                DeviceEnrollmentCapability::new(capability)?,
                observed_head.hash(),
                candidate_device_add.clone(),
            )?,
            DeviceSessionCredential::new(provider.session_id, provider.session_secret)?,
            UtcMillis::new(NOW + 3)?,
        )
        .await?
    {
        IdentityAppendOutcome::Committed(receipt) => receipt.head(),
        other => return Err(format!("history approval failed: {other:?}").into()),
    };
    let device_add_bytes = candidate_device_add.clone();
    let provider_response =
        history_testkit::ready_provider_response(&history_testkit::ProviderResponseInput {
            request: recovered.request_id,
            identity: owner.identity_id,
            catalog_id,
            generation: 1,
            catalog_head_digest: *catalog_head_digest.as_bytes(),
            preparation: &preparation,
            signed_head: &catalog_head,
            observed_head_sequence: observed_head.sequence().get(),
            observed_head_hash: *observed_head.hash().as_bytes(),
            successor_head_sequence: recovered.approved_head.sequence().get(),
            successor_head_hash: *recovered.approved_head.hash().as_bytes(),
            candidate_device: recovered.active.device_id,
            candidate_recipient: [218; 32],
            device_add: &device_add_bytes,
            provider_device: provider.device_id,
            provider_signer: &provider_signer,
            authority_device: owner.device_id,
            authority_signer: &owner_device_signer,
            response_idempotency_key: "mailbox-provider-0001",
            issued_at: 4_000,
            expires_at: 90_000,
        });
    let provider_path = RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_PATH_TEMPLATE
        .replace("{request_id}", &recovered.request_id.to_string());
    let provider_request =
        history_testkit::HttpRequest::new("PUT", provider_path, provider_response.clone())
            .header(
                "content-type",
                RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_CONTENT_TYPE,
            )
            .header(
                "accept",
                RECOVERY_SCOPE_CATALOG_PROVIDER_RESPONSE_RECEIPT_CONTENT_TYPE,
            )
            .header("idempotency-key", "mailbox-provider-0001")
            .header(
                "authorization",
                device_session_authorization(provider.session_id, provider.session_secret),
            );
    let provider_result =
        send_history_testkit_request(identity_app.clone(), provider_request).await?;
    assert!(
        matches!(provider_result.status, 200 | 201),
        "provider status {} code {:?}",
        provider_result.status,
        serde_json::from_slice::<serde_json::Value>(&provider_result.body)
            .ok()
            .and_then(|v| v
                .pointer("/error/code")
                .and_then(|v| v.as_str())
                .map(str::to_owned))
    );
    let v4_request = history_testkit::request_v4(
        recovered.request_id,
        owner.identity_id,
        recovered.active.device_id,
        &candidate,
        [218; 32],
        observed_head.sequence().get(),
        *observed_head.hash().as_bytes(),
        recovered.approved_head.sequence().get(),
        *recovered.approved_head.hash().as_bytes(),
        &device_add_bytes,
        &preparation,
        catalog_id,
        &catalog_head,
        *catalog_head_digest.as_bytes(),
        response_capability,
        "mailbox-request-v4-0001",
        6_000,
        90_000,
    );
    let v4_request = history_testkit::HttpRequest::new(
        "POST",
        dtx_identity_node::HISTORY_RECOVERY_REQUEST_V4_PATH,
        v4_request,
    )
    .header(
        "content-type",
        dtx_identity_node::HISTORY_RECOVERY_REQUEST_V4_CONTENT_TYPE,
    )
    .header(
        "accept",
        dtx_identity_node::HISTORY_RECOVERY_REQUEST_RECEIPT_V4_CONTENT_TYPE,
    )
    .header("idempotency-key", "mailbox-request-v4-0001")
    .header(
        DEVICE_ENROLLMENT_CAPABILITY_HEADER,
        Base64UrlUnpadded::encode_string(&capability),
    )
    .header(
        RECOVERY_RESPONSE_CAPABILITY_HEADER,
        Base64UrlUnpadded::encode_string(&response_capability),
    );
    let v4_result = send_history_testkit_request(identity_app.clone(), v4_request).await?;
    assert!(
        matches!(v4_result.status, 200 | 201),
        "v4 status {} code {:?}",
        v4_result.status,
        serde_json::from_slice::<serde_json::Value>(&v4_result.body)
            .ok()
            .and_then(|v| v
                .pointer("/error/code")
                .and_then(|v| v.as_str())
                .map(str::to_owned))
    );
    let request_row = sqlx::query(
        "SELECT request_digest,manifest_digest FROM identity.history_recovery_requests WHERE request_id=$1",
    )
    .bind(*recovered.request_id.as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    let request_digest = Sha256Digest::from_bytes(
        request_row
            .try_get::<Vec<u8>, _>("request_digest")?
            .try_into()
            .map_err(|_| "request digest length")?,
    );
    let manifest_digest = Sha256Digest::from_bytes(
        request_row
            .try_get::<Vec<u8>, _>("manifest_digest")?
            .try_into()
            .map_err(|_| "manifest digest length")?,
    );
    let provider_response_digest = Sha256Digest::hash_domain(
        b"dirextalk.recovery-scope-catalog-handoff-provider-response.v2\0",
        &provider_response,
    );
    let offer = history_testkit::offer_v3(
        recovered.request_id,
        *request_digest.as_bytes(),
        *manifest_digest.as_bytes(),
        catalog_id,
        1,
        *catalog_head_digest.as_bytes(),
        recovered.active.device_id,
        *Sha256Digest::hash_domain(history_testkit::RECIPIENT_KEY_HASH_DOMAIN, &[218; 32])
            .as_bytes(),
        b"opaque-recipient-offer",
        *provider_response_digest.as_bytes(),
        6_000,
        90_000,
    );
    let provider_descriptor = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(provider.device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            public_key(&provider_signer)?.to_canonical_value(),
        ),
    ]);
    let authority_descriptor = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(owner.device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            public_key(&owner_device_signer)?.to_canonical_value(),
        ),
    ]);
    let mailbox_id = MailboxId::new();
    let envelope_id = EnvelopeId::new();
    let write_capability = [230; 32];
    let registration = mailbox_registration_body(
        mailbox_id,
        owner.identity_id,
        owner.device_id,
        write_capability,
        UtcMillis::new(100_000)?,
    )?;
    let registration_response = send_registration(
        mailbox_app.clone(),
        "mailbox-register-0001",
        owner.session_id,
        owner.session_secret,
        mailbox_id,
        registration,
    )
    .await?;
    assert_eq!(registration_response.status(), StatusCode::CREATED);
    let idempotency_digest = Sha256Digest::hash_domain(
        b"dirextalk.history-recovery.grant-idempotency.v5\0",
        b"mailbox-grant-0001",
    );
    let grant = history_testkit::grant_v5(
        owner.identity_id,
        recovered.request_id,
        *request_digest.as_bytes(),
        *manifest_digest.as_bytes(),
        catalog_id,
        1,
        &catalog_head,
        *catalog_head_digest.as_bytes(),
        [31; 32],
        1,
        *Sha256Digest::hash_domain(
            history_testkit::HISTORY_LEAF_SET_DOMAIN,
            &encode_deterministic_cbor(&CanonicalValue::Array(vec![CanonicalValue::Bytes(
                vec![31; 32],
            )]))?,
        )
        .as_bytes(),
        recovered.active.device_id,
        &candidate,
        [218; 32],
        observed_head.sequence().get(),
        *observed_head.hash().as_bytes(),
        recovered.approved_head.sequence().get(),
        *recovered.approved_head.hash().as_bytes(),
        *Sha256Digest::hash_domain(
            history_testkit::IDENTITY_DEVICE_ADD_DOMAIN,
            &device_add_bytes,
        )
        .as_bytes(),
        *Sha256Digest::hash_domain(history_testkit::PREPARATION_DIGEST_DOMAIN, &preparation)
            .as_bytes(),
        provider_descriptor.clone(),
        authority_descriptor.clone(),
        *mailbox_id.as_uuid(),
        *envelope_id.as_uuid(),
        0,
        Uuid::now_v7(),
        6_000,
        90_000,
        &provider_signer,
        &owner_device_signer,
        &offer,
        *idempotency_digest.as_bytes(),
        5_000,
        100_000,
    );
    let parsed_grant =
        dtx_mailbox::DeviceHistoryGrantV5Command::parse(grant.clone(), idempotency_digest);
    assert!(
        parsed_grant.is_ok(),
        "testkit grant parse error: {parsed_grant:?}"
    );
    let (first_result, concurrent_result) = tokio::join!(
        send_v2(
            mailbox_app.clone(),
            DEVICE_HISTORY_GRANT_V5_PATH,
            DEVICE_HISTORY_GRANT_V5_CONTENT_TYPE,
            Some("mailbox-grant-0001"),
            provider.session_id,
            provider.session_secret,
            grant.clone(),
        ),
        send_v2(
            mailbox_app.clone(),
            DEVICE_HISTORY_GRANT_V5_PATH,
            DEVICE_HISTORY_GRANT_V5_CONTENT_TYPE,
            Some("mailbox-grant-0001"),
            provider.session_id,
            provider.session_secret,
            grant.clone(),
        )
    );
    let first = first_result?;
    let concurrent = concurrent_result?;
    assert!(
        matches!(
            (first.status(), concurrent.status()),
            (StatusCode::CREATED, StatusCode::OK) | (StatusCode::OK, StatusCode::CREATED)
        ),
        "concurrent grant statuses: {} and {}",
        first.status(),
        concurrent.status()
    );
    assert_content_type(&first, DEVICE_HISTORY_GRANT_RECEIPT_V5_CONTENT_TYPE);
    assert_content_type(&concurrent, DEVICE_HISTORY_GRANT_RECEIPT_V5_CONTENT_TYPE);
    let receipt = response_bytes(first).await?;
    assert_eq!(response_bytes(concurrent).await?, receipt);
    let replay = send_v2(
        mailbox_app.clone(),
        DEVICE_HISTORY_GRANT_V5_PATH,
        DEVICE_HISTORY_GRANT_V5_CONTENT_TYPE,
        Some("mailbox-grant-0001"),
        provider.session_id,
        provider.session_secret,
        grant.clone(),
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(response_bytes(replay).await?, receipt);
    let grant_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM messaging.history_recovery_grants_v4 WHERE identity_id=$1",
    )
    .bind(owner.identity_id.to_string())
    .fetch_one(harness.admin_pool())
    .await?;
    let envelope_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM messaging.mailbox_envelopes WHERE mailbox_id=$1")
            .bind(*mailbox_id.as_uuid())
            .fetch_one(harness.admin_pool())
            .await?;
    assert_eq!((grant_count, envelope_count), (1, 1));

    let mismatch = history_testkit::grant_v5(
        owner.identity_id,
        recovered.request_id,
        *request_digest.as_bytes(),
        *manifest_digest.as_bytes(),
        catalog_id,
        1,
        &catalog_head,
        *catalog_head_digest.as_bytes(),
        [31; 32],
        1,
        *Sha256Digest::hash_domain(
            history_testkit::HISTORY_LEAF_SET_DOMAIN,
            &encode_deterministic_cbor(&CanonicalValue::Array(vec![CanonicalValue::Bytes(
                vec![31; 32],
            )]))?,
        )
        .as_bytes(),
        recovered.active.device_id,
        &candidate,
        [218; 32],
        observed_head.sequence().get(),
        *observed_head.hash().as_bytes(),
        recovered.approved_head.sequence().get(),
        *recovered.approved_head.hash().as_bytes(),
        *Sha256Digest::hash_domain(
            history_testkit::IDENTITY_DEVICE_ADD_DOMAIN,
            &device_add_bytes,
        )
        .as_bytes(),
        *Sha256Digest::hash_domain(history_testkit::PREPARATION_DIGEST_DOMAIN, &preparation)
            .as_bytes(),
        provider_descriptor,
        authority_descriptor,
        *mailbox_id.as_uuid(),
        *EnvelopeId::new().as_uuid(),
        0,
        Uuid::now_v7(),
        6_000,
        100_000,
        &provider_signer,
        &owner_device_signer,
        &offer,
        *idempotency_digest.as_bytes(),
        5_000,
        100_000,
    );
    let conflict = send_v2(
        mailbox_app,
        DEVICE_HISTORY_GRANT_V5_PATH,
        DEVICE_HISTORY_GRANT_V5_CONTENT_TYPE,
        Some("mailbox-grant-0001"),
        provider.session_id,
        provider.session_secret,
        mismatch,
    )
    .await?;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!((grant_count, envelope_count), (1, 1));
    Ok(())
}
