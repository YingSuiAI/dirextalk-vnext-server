#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one HTTP/SQL regression protects an approved QR enrollment when its first success response is lost"
)]
async fn approved_device_enrollment_replays_after_approving_session_is_revoked()
-> Result<(), Box<dyn Error>> {
    const ENROLLMENT_CHALLENGE_KEY: &str = "device-enrollment-challenge-0001";
    const ENROLLMENT_APPROVAL_KEY: &str = "device-enrollment-approval-0001";
    const DIFFERENT_ENROLLMENT_APPROVAL_KEY: &str = "device-enrollment-approval-0002";

    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            store.clone(),
            Arc::new(FixedClock(2_000)),
            AUDIENCE,
        ),
    );

    let root = signing_key(41);
    let recovery = signing_key(42);
    let genesis = genesis(&root, &recovery, 1_000)?;
    let identity_id = genesis.identity_id();
    let bootstrap = send_event(
        app.clone(),
        IDENTITY_BOOTSTRAP_PATH,
        "device-enrollment-bootstrap-0001",
        None,
        genesis.to_deterministic_cbor()?,
    )
    .await?;
    assert_eq!(bootstrap.status(), StatusCode::CREATED);

    let approving_device = signing_key(43);
    let approving_device_id = DeviceId::new();
    let initial_device = device_add(
        &root,
        &approving_device,
        identity_id,
        approving_device_id,
        genesis.entry_hash()?,
        2,
        1_100,
    )?;
    let initial_head_hash = initial_device.entry_hash()?;
    let initial = send_event(
        app.clone(),
        INITIAL_DEVICE_ENROLL_PATH,
        "device-enrollment-initial-0001",
        Some(genesis.entry_hash()?),
        initial_device.to_deterministic_cbor()?,
    )
    .await?;
    assert_eq!(initial.status(), StatusCode::CREATED);

    let session_challenge = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(DEVICE_SESSION_CHALLENGE_PATH)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "identity_id": identity_id,
                    "device_id": approving_device_id,
                }))?))?,
        )
        .await?;
    assert_eq!(session_challenge.status(), StatusCode::CREATED);
    let session_challenge: serde_json::Value =
        serde_json::from_slice(&to_bytes(session_challenge.into_body(), 16_384).await?)?;
    let session_challenge_id: DeviceSessionChallengeId = session_challenge
        .pointer("/challenge_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("device session challenge ID missing")?
        .parse()?;
    let session_challenge_nonce = decode_32(
        session_challenge
            .pointer("/challenge_nonce")
            .and_then(serde_json::Value::as_str)
            .ok_or("device session challenge nonce missing")?,
    )?;
    let session_expires_at = UtcMillis::new(
        session_challenge
            .pointer("/session_expires_at_ms")
            .and_then(serde_json::Value::as_i64)
            .ok_or("device session expiry missing")?,
    )?;
    let approving_session_id = DeviceSessionId::new();
    let approving_session_secret = [44_u8; 32];
    let session_secret_hash =
        Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &approving_session_secret);
    let session_completion = send_session(
        app.clone(),
        "device-enrollment-session-0001",
        json!({
            "identity_id": identity_id,
            "device_id": approving_device_id,
            "challenge_id": session_challenge_id,
            "session_id": approving_session_id,
            "challenge_nonce": Base64UrlUnpadded::encode_string(&session_challenge_nonce),
            "session_secret": Base64UrlUnpadded::encode_string(&approving_session_secret),
            "proof": signature(
                &approving_device,
                &device_session_proof_input(
                    identity_id,
                    approving_device_id,
                    session_challenge_id,
                    &session_challenge_nonce,
                    AUDIENCE,
                    approving_session_id,
                    session_secret_hash,
                    session_expires_at,
                )?,
            ),
        }),
    )
    .await?;
    assert_eq!(session_completion.status(), StatusCode::CREATED);

    let candidate_device = signing_key(45);
    let candidate_device_id = DeviceId::new();
    let enrollment_capability = [46_u8; 32];
    let candidate_request = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(candidate_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Bytes(public_key(&candidate_device)?.as_bytes().to_vec()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Bytes(vec![8; 32]),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Bytes(enrollment_capability.to_vec()),
        ),
    ]))?;
    let candidate_response = send_device_enrollment_challenge(
        app.clone(),
        ENROLLMENT_CHALLENGE_KEY,
        DEVICE_ENROLLMENT_CANDIDATE_CONTENT_TYPE,
        candidate_request,
    )
    .await?;
    assert_eq!(candidate_response.status(), StatusCode::CREATED);
    let candidate_response = to_bytes(candidate_response.into_body(), 16_384).await?;
    let enrollment_challenge_id = enrollment_challenge_id(&candidate_response)?;

    let enrollment_event = device_add_with_encryption(
        &root,
        &candidate_device,
        &DeviceAddInput {
            identity_id,
            device_id: candidate_device_id,
            previous_hash: initial_head_hash,
            sequence: 3,
            occurred_at: 1_200,
            encryption_key: [8_u8; 32],
        },
    )?;
    let enrollment_body = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(enrollment_challenge_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Bytes(enrollment_capability.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Bytes(enrollment_event.to_deterministic_cbor()?),
        ),
    ]))?;
    let approved = send_device_enrollment_approval(
        app.clone(),
        ENROLLMENT_APPROVAL_KEY,
        approving_session_id,
        approving_session_secret,
        initial_head_hash,
        enrollment_body.clone(),
    )
    .await?;
    assert_eq!(approved.status(), StatusCode::CREATED);
    let approved_receipt = to_bytes(approved.into_body(), 16_384).await?.to_vec();
    assert!(!approved_receipt.is_empty());
    assert_identity_entry_count(harness.identity_runtime_pool(), identity_id, 3).await?;

    // Simulate a later revoke after the approval committed but before a caller
    // can retry the response-lost approval request. The direct append is only
    // the test setup for server-side state; both approval attempts above/below
    // traverse the public HTTP boundary.
    let repository = IdentityLogRepository::new();
    let enrollment_head = repository
        .load(&store, identity_id)
        .await?
        .ok_or("identity log missing before device session revoke")?
        .head();
    let revoke = signed_event(
        &root,
        identity_id,
        4,
        Some(enrollment_head.hash()),
        3_000,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: approving_device_id,
        },
    )?;
    let revoke_command = IdentityAppendCommand::new(
        Sha256Digest::hash_domain(b"test-device-enrollment-revoke\0", b"1"),
        Some(enrollment_head),
        revoke.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        repository
            .append(&store, &revoke_command, UtcMillis::new(3_000)?)
            .await?,
        IdentityAppendOutcome::Committed(_)
    ));
    let credential = DeviceSessionCredential::new(approving_session_id, approving_session_secret)?;
    assert!(matches!(
        DeviceSessionRepository
            .authenticate(&store, &credential, UtcMillis::new(3_001)?)
            .await,
        Err(dtx_identity_persistence::IdentityPersistenceError::DeviceAuthenticationRejected)
    ));

    let replay = send_device_enrollment_approval(
        app.clone(),
        ENROLLMENT_APPROVAL_KEY,
        approving_session_id,
        approving_session_secret,
        initial_head_hash,
        enrollment_body.clone(),
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(replay.into_body(), 16_384).await?.to_vec(),
        approved_receipt
    );

    let different_idempotency_key = send_device_enrollment_approval(
        app,
        DIFFERENT_ENROLLMENT_APPROVAL_KEY,
        approving_session_id,
        approving_session_secret,
        initial_head_hash,
        enrollment_body,
    )
    .await?;
    assert_eq!(different_idempotency_key.status(), StatusCode::CONFLICT);
    assert_safe_error(different_idempotency_key, "IDEMPOTENCY_CONFLICT").await?;
    assert_identity_entry_count(harness.identity_runtime_pool(), identity_id, 4).await?;
    Ok(())
}
