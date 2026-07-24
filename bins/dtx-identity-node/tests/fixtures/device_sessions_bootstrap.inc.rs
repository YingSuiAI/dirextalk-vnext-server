#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one security-boundary test keeps bootstrap, first-device, session replay, consumption, and revoke assertions coherent"
)]
async fn initial_device_and_short_session_are_self_authenticated_replayable_and_revocable()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            store.clone(),
            Arc::new(FixedClock(2_000)),
            AUDIENCE,
        ),
    );

    let root = signing_key(1);
    let recovery = signing_key(2);
    let genesis = genesis(&root, &recovery, 1_000)?;
    let identity_id = genesis.identity_id();
    let genesis_bytes = genesis.to_deterministic_cbor()?;
    let bootstrap = send_event(
        app.clone(),
        IDENTITY_BOOTSTRAP_PATH,
        BOOTSTRAP_KEY,
        None,
        genesis_bytes,
    )
    .await?;
    assert_eq!(bootstrap.status(), StatusCode::CREATED);
    assert_eq!(
        bootstrap
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(IDENTITY_APPEND_RECEIPT_CONTENT_TYPE)
    );

    let device = signing_key(3);
    let device_id = DeviceId::new();
    let initial = device_add(
        &root,
        &device,
        identity_id,
        device_id,
        genesis.entry_hash()?,
        2,
        1_100,
    )?;
    let initial_bytes = initial.to_deterministic_cbor()?;
    let initial_response = send_event(
        app.clone(),
        INITIAL_DEVICE_ENROLL_PATH,
        INITIAL_DEVICE_KEY,
        Some(genesis.entry_hash()?),
        initial_bytes.clone(),
    )
    .await?;
    assert_eq!(initial_response.status(), StatusCode::CREATED);
    let initial_receipt = to_bytes(initial_response.into_body(), 16_384)
        .await?
        .to_vec();
    let initial_replay = send_event(
        app.clone(),
        INITIAL_DEVICE_ENROLL_PATH,
        INITIAL_DEVICE_KEY,
        Some(genesis.entry_hash()?),
        initial_bytes,
    )
    .await?;
    assert_eq!(initial_replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(initial_replay.into_body(), 16_384).await?.to_vec(),
        initial_receipt
    );
    assert_identity_entry_count(harness.identity_runtime_pool(), identity_id, 2).await?;

    let challenge_request = Request::builder()
        .method("POST")
        .uri(DEVICE_SESSION_CHALLENGE_PATH)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({
            "identity_id": identity_id,
            "device_id": device_id,
        }))?))?;
    let challenge_response = app.clone().oneshot(challenge_request).await?;
    assert_eq!(challenge_response.status(), StatusCode::CREATED);
    let challenge: serde_json::Value =
        serde_json::from_slice(&to_bytes(challenge_response.into_body(), 16_384).await?)?;
    let challenge_id: DeviceSessionChallengeId = challenge
        .pointer("/challenge_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("challenge ID missing")?
        .parse()?;
    let challenge_nonce = decode_32(
        challenge
            .pointer("/challenge_nonce")
            .and_then(serde_json::Value::as_str)
            .ok_or("challenge nonce missing")?,
    )?;
    assert_eq!(
        challenge
            .pointer("/audience")
            .and_then(serde_json::Value::as_str),
        Some(AUDIENCE)
    );
    let session_expires_at = UtcMillis::new(
        challenge
            .pointer("/session_expires_at_ms")
            .and_then(serde_json::Value::as_i64)
            .ok_or("session expiry missing")?,
    )?;
    assert_challenge_stores_only_hash(
        harness.identity_runtime_pool(),
        challenge_id,
        challenge_nonce,
    )
    .await?;
    let rate_limited = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(DEVICE_SESSION_CHALLENGE_PATH)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "identity_id": identity_id,
                    "device_id": device_id,
                }))?))?,
        )
        .await?;
    assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_safe_error(rate_limited, "DEVICE_SESSION_CHALLENGE_RATE_LIMITED").await?;

    let session_id = DeviceSessionId::new();
    let session_secret = [9_u8; 32];
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &session_secret);
    let proof = signature(
        &device,
        &device_session_proof_input(
            identity_id,
            device_id,
            challenge_id,
            &challenge_nonce,
            AUDIENCE,
            session_id,
            session_secret_hash,
            session_expires_at,
        )?,
    );
    let completion_body = json!({
        "identity_id": identity_id,
        "device_id": device_id,
        "challenge_id": challenge_id,
        "session_id": session_id,
        "challenge_nonce": Base64UrlUnpadded::encode_string(&challenge_nonce),
        "session_secret": Base64UrlUnpadded::encode_string(&session_secret),
        "proof": proof,
    });
    let completion = send_session(app.clone(), SESSION_KEY, completion_body.clone()).await?;
    assert_eq!(completion.status(), StatusCode::CREATED);
    assert_eq!(
        completion
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(DEVICE_SESSION_RECEIPT_CONTENT_TYPE)
    );
    let receipt = to_bytes(completion.into_body(), 16_384).await?.to_vec();
    let replay = send_session(app.clone(), SESSION_KEY, completion_body.clone()).await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(replay.into_body(), 16_384).await?.to_vec(),
        receipt
    );
    assert_session_count(harness.identity_runtime_pool(), 1).await?;

    let mut altered = completion_body.clone();
    altered["session_secret"] =
        serde_json::Value::String(Base64UrlUnpadded::encode_string(&[8_u8; 32]));
    let idempotency_conflict = send_session(app.clone(), SESSION_KEY, altered).await?;
    assert_eq!(idempotency_conflict.status(), StatusCode::CONFLICT);
    assert_safe_error(idempotency_conflict, "IDEMPOTENCY_CONFLICT").await?;

    let consumed = send_session(app.clone(), SESSION_RETRY_KEY, completion_body).await?;
    assert_eq!(consumed.status(), StatusCode::CONFLICT);
    assert_safe_error(consumed, "DEVICE_SESSION_CHALLENGE_CONSUMED").await?;
    assert_session_count(harness.identity_runtime_pool(), 1).await?;

    let credential = DeviceSessionCredential::new(session_id, session_secret)?;
    let authenticated = DeviceSessionRepository
        .authenticate(&store, &credential, UtcMillis::new(2_001)?)
        .await?;
    assert_eq!(authenticated.identity_id(), identity_id);
    assert_eq!(authenticated.device_id(), device_id);

    let mut authorization = HeaderMap::new();
    authorization.insert(
        header::AUTHORIZATION,
        format!(
            "{DEVICE_SESSION_AUTHORIZATION_SCHEME} {session_id}.{}",
            Base64UrlUnpadded::encode_string(&session_secret)
        )
        .parse()?,
    );
    let parsed_credential = parse_device_session_authorization(&authorization)?;
    assert_eq!(parsed_credential.session_id(), session_id);
    let parsed_authenticated = DeviceSessionRepository
        .authenticate(&store, &parsed_credential, UtcMillis::new(2_001)?)
        .await?;
    assert_eq!(parsed_authenticated.device_id(), device_id);
    authorization.append(header::AUTHORIZATION, "Bearer ignored".parse()?);
    assert!(parse_device_session_authorization(&authorization).is_err());

    let expired = DeviceSessionRepository
        .authenticate(&store, &credential, session_expires_at)
        .await;
    assert!(matches!(
        expired,
        Err(dtx_identity_persistence::IdentityPersistenceError::DeviceAuthenticationRejected)
    ));

    let expired_challenge = DeviceSessionRepository
        .issue_challenge(
            &store,
            identity_id,
            device_id,
            [7_u8; 32],
            AUDIENCE,
            UtcMillis::new(20_000)?,
        )
        .await?;
    let expired_session_id = DeviceSessionId::new();
    let expired_session_secret = [6_u8; 32];
    let expired_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &expired_session_secret);
    let expired_proof = signature(
        &device,
        &device_session_proof_input(
            identity_id,
            device_id,
            expired_challenge.challenge_id(),
            expired_challenge.nonce(),
            AUDIENCE,
            expired_session_id,
            expired_secret_hash,
            expired_challenge.session_expires_at(),
        )?,
    );
    let expired_app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            store.clone(),
            Arc::new(FixedClock(expired_challenge.expires_at().get())),
            AUDIENCE,
        ),
    );
    let expired_completion = send_session(
        expired_app,
        EXPIRED_SESSION_KEY,
        json!({
            "identity_id": identity_id,
            "device_id": device_id,
            "challenge_id": expired_challenge.challenge_id(),
            "session_id": expired_session_id,
            "challenge_nonce": Base64UrlUnpadded::encode_string(expired_challenge.nonce()),
            "session_secret": Base64UrlUnpadded::encode_string(&expired_session_secret),
            "proof": expired_proof,
        }),
    )
    .await?;
    assert_eq!(expired_completion.status(), StatusCode::CONFLICT);
    assert_safe_error(expired_completion, "DEVICE_SESSION_CHALLENGE_EXPIRED").await?;

    let repository = IdentityLogRepository::new();
    let head = repository
        .load(&store, identity_id)
        .await?
        .ok_or("identity log missing before revoke")?
        .head();
    let revoke = signed_event(
        &root,
        identity_id,
        3,
        Some(head.hash()),
        30_000,
        IdentityLogEventPayloadV1::DeviceRevoke { device_id },
    )?;
    let revoke_command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-device-session-revoke\0", b"1"),
        Some(head),
        revoke.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append(&store, &revoke_command, UtcMillis::new(30_000)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let revoked = DeviceSessionRepository
        .authenticate(&store, &credential, UtcMillis::new(2_101)?)
        .await;
    assert!(matches!(
        revoked,
        Err(dtx_identity_persistence::IdentityPersistenceError::DeviceAuthenticationRejected)
    ));
    let removed = DeviceSessionRepository
        .prune_expired(&store, expired_challenge.session_expires_at())
        .await?;
    assert_eq!(removed, 5);
    assert_device_session_state_counts(harness.identity_runtime_pool(), (0, 0, 0, 0)).await?;
    Ok(())
}
