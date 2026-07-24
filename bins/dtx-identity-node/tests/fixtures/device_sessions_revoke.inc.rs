#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL HTTP boundary test protects revoke authorization, exact replay, and target binding"
)]
async fn another_device_revoke_is_root_signed_session_gated_and_exactly_replayable()
-> Result<(), Box<dyn Error>> {
    const REVOKE_KEY: &str = "device-revoke-command-0001";
    const REVOKE_SELF_KEY: &str = "device-revoke-command-0002";
    const REVOKE_AFTER_SESSION_KEY: &str = "device-revoke-command-0003";

    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let repository = IdentityLogRepository::new();
    let root = signing_key(61);
    let recovery = signing_key(62);
    let genesis = genesis(&root, &recovery, 1_000)?;
    let identity_id = genesis.identity_id();
    let genesis_command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-device-revoke-bootstrap\0", b"1"),
        None,
        genesis.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append(&store, &genesis_command, UtcMillis::new(1_000)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));

    let initiator = signing_key(63);
    let initiator_device_id = DeviceId::new();
    let initiator_add = device_add(
        &root,
        &initiator,
        identity_id,
        initiator_device_id,
        genesis.entry_hash()?,
        2,
        1_100,
    )?;
    let genesis_head = repository
        .load(&store, identity_id)
        .await?
        .ok_or("identity missing after bootstrap")?
        .head();
    let initiator_add_command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-device-revoke-add\0", b"1"),
        Some(genesis_head),
        initiator_add.to_deterministic_cbor()?,
    )?;
    repository
        .append(&store, &initiator_add_command, UtcMillis::new(1_100)?)
        .await?;

    let target = signing_key(64);
    let target_device_id = DeviceId::new();
    let target_add = device_add_with_encryption(
        &root,
        &target,
        &DeviceAddInput {
            identity_id,
            device_id: target_device_id,
            previous_hash: initiator_add.entry_hash()?,
            sequence: 3,
            occurred_at: 1_200,
            encryption_key: [8_u8; 32],
        },
    )?;
    let initiator_head = repository
        .load(&store, identity_id)
        .await?
        .ok_or("identity missing after initiator enrollment")?
        .head();
    let target_add_command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-device-revoke-add\0", b"2"),
        Some(initiator_head),
        target_add.to_deterministic_cbor()?,
    )?;
    repository
        .append(&store, &target_add_command, UtcMillis::new(1_200)?)
        .await?;

    let session_nonce = [65_u8; 32];
    let challenge = DeviceSessionRepository
        .issue_challenge(
            &store,
            identity_id,
            initiator_device_id,
            session_nonce,
            AUDIENCE,
            UtcMillis::new(1_300)?,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let session_secret = [66_u8; 32];
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let session_proof = signature(
        &initiator,
        &device_session_proof_input(
            identity_id,
            initiator_device_id,
            challenge.challenge_id(),
            challenge.nonce(),
            AUDIENCE,
            session_id,
            session_secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    let session_completion = DeviceSessionCompletionCommand::new(
        Sha256Digest::hash_domain(b"test-device-revoke-session\0", b"1"),
        identity_id,
        initiator_device_id,
        challenge.challenge_id(),
        session_id,
        session_nonce,
        session_secret,
        session_proof,
    )?;
    DeviceSessionRepository
        .complete(&store, &session_completion, UtcMillis::new(1_301)?)
        .await?;

    let app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            store.clone(),
            Arc::new(FixedClock(1_400)),
            AUDIENCE,
        ),
    );
    let target_head = repository
        .load(&store, identity_id)
        .await?
        .ok_or("identity missing after target enrollment")?
        .head();
    let revoke_target = signed_event(
        &root,
        identity_id,
        4,
        Some(target_head.hash()),
        1_400,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: target_device_id,
        },
    )?;
    let revoke_target_bytes = revoke_target.to_deterministic_cbor()?;

    let invalid_session = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        [99_u8; 32],
        identity_id,
        target_device_id,
        target_head.hash(),
        revoke_target_bytes.clone(),
    )
    .await?;
    assert_eq!(invalid_session.status(), StatusCode::UNAUTHORIZED);
    assert_safe_error(invalid_session, "DEVICE_AUTHENTICATION_FAILED").await?;

    let route_target_mismatch = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        session_secret,
        identity_id,
        DeviceId::new(),
        target_head.hash(),
        revoke_target_bytes.clone(),
    )
    .await?;
    assert_eq!(
        route_target_mismatch.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_safe_error(route_target_mismatch, "DEVICE_REVOKE_INVALID").await?;

    let revoke_current_session = signed_event(
        &root,
        identity_id,
        4,
        Some(target_head.hash()),
        1_400,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: initiator_device_id,
        },
    )?;
    let current_session_rejected = send_device_revoke(
        app.clone(),
        REVOKE_SELF_KEY,
        session_id,
        session_secret,
        identity_id,
        initiator_device_id,
        target_head.hash(),
        revoke_current_session.to_deterministic_cbor()?,
    )
    .await?;
    assert_eq!(current_session_rejected.status(), StatusCode::CONFLICT);
    assert_safe_error(
        current_session_rejected,
        "DEVICE_REVOKE_CURRENT_SESSION_FORBIDDEN",
    )
    .await?;

    let committed = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        session_secret,
        identity_id,
        target_device_id,
        target_head.hash(),
        revoke_target_bytes.clone(),
    )
    .await?;
    assert_eq!(committed.status(), StatusCode::CREATED);
    assert_eq!(
        committed
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(IDENTITY_APPEND_RECEIPT_CONTENT_TYPE)
    );
    let exact_receipt = to_bytes(committed.into_body(), 16_384).await?.to_vec();

    let response_loss_replay = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        session_secret,
        identity_id,
        target_device_id,
        target_head.hash(),
        revoke_target_bytes.clone(),
    )
    .await?;
    assert_eq!(response_loss_replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response_loss_replay.into_body(), 16_384)
            .await?
            .to_vec(),
        exact_receipt
    );

    let altered_revoke = signed_event(
        &root,
        identity_id,
        4,
        Some(target_head.hash()),
        1_401,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: target_device_id,
        },
    )?;
    let key_body_conflict = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        session_secret,
        identity_id,
        target_device_id,
        target_head.hash(),
        altered_revoke.to_deterministic_cbor()?,
    )
    .await?;
    assert_eq!(key_body_conflict.status(), StatusCode::CONFLICT);
    assert_safe_error(key_body_conflict, "IDEMPOTENCY_CONFLICT").await?;

    let post_target_revoke_replay = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        session_secret,
        identity_id,
        target_device_id,
        target_head.hash(),
        revoke_target_bytes.clone(),
    )
    .await?;
    assert_eq!(post_target_revoke_replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(post_target_revoke_replay.into_body(), 16_384)
            .await?
            .to_vec(),
        exact_receipt
    );

    let head_after_target_revoke = repository
        .load(&store, identity_id)
        .await?
        .ok_or("identity missing after target revoke")?
        .head();
    let revoke_initiator = signed_event(
        &root,
        identity_id,
        5,
        Some(head_after_target_revoke.hash()),
        1_500,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: initiator_device_id,
        },
    )?;
    let revoke_initiator_command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-device-revoke-initiator\0", b"1"),
        Some(head_after_target_revoke),
        revoke_initiator.to_deterministic_cbor()?,
    )?;
    repository
        .append(&store, &revoke_initiator_command, UtcMillis::new(1_500)?)
        .await?;

    let revoked_initiator_exact_replay = send_device_revoke(
        app.clone(),
        REVOKE_KEY,
        session_id,
        session_secret,
        identity_id,
        target_device_id,
        target_head.hash(),
        revoke_target_bytes.clone(),
    )
    .await?;
    assert_eq!(revoked_initiator_exact_replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(revoked_initiator_exact_replay.into_body(), 16_384)
            .await?
            .to_vec(),
        exact_receipt
    );

    let revoked_initiator_new_command = send_device_revoke(
        app,
        REVOKE_AFTER_SESSION_KEY,
        session_id,
        session_secret,
        identity_id,
        target_device_id,
        target_head.hash(),
        revoke_target_bytes,
    )
    .await?;
    assert_eq!(
        revoked_initiator_new_command.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_safe_error(
        revoked_initiator_new_command,
        "DEVICE_AUTHENTICATION_FAILED",
    )
    .await?;
    assert_identity_entry_count(harness.identity_runtime_pool(), identity_id, 5).await?;
    Ok(())
}
