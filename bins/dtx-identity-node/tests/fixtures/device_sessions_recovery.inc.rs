#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one HTTP/PostgreSQL boundary keeps the V2 recovery request, replay, conflicts, and secret persistence coherent"
)]
async fn history_recovery_v2_request_is_exact_replay_safe_and_capability_private()
-> Result<(), Box<dyn Error>> {
    const REQUEST_KEY: &str = "history-recovery-request-0001";
    const DIFFERENT_REQUEST_KEY: &str = "history-recovery-request-0002";

    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            store.clone(),
            Arc::new(FixedClock(2_000)),
            AUDIENCE,
        ),
    );

    let root = signing_key(31);
    let recovery = signing_key(32);
    let genesis = genesis(&root, &recovery, 1_000)?;
    let identity_id = genesis.identity_id();
    assert_eq!(
        send_event(
            app.clone(),
            IDENTITY_BOOTSTRAP_PATH,
            "history-recovery-bootstrap-0001",
            None,
            genesis.to_deterministic_cbor()?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );

    let initial_device = signing_key(33);
    let initial_device_id = DeviceId::new();
    assert_eq!(
        send_event(
            app.clone(),
            INITIAL_DEVICE_ENROLL_PATH,
            "history-recovery-initial-0001",
            Some(genesis.entry_hash()?),
            device_add(
                &root,
                &initial_device,
                identity_id,
                initial_device_id,
                genesis.entry_hash()?,
                2,
                1_100,
            )?
            .to_deterministic_cbor()?,
        )
        .await?
        .status(),
        StatusCode::CREATED,
    );
    let observed_head = IdentityLogRepository::new()
        .load(&store, identity_id)
        .await?
        .ok_or("identity missing before history recovery request")?
        .head();

    let candidate = signing_key(34);
    let recipient_encryption_key = DeviceEncryptionPublicKey::try_from([35_u8; 32])?;
    let request_id = DeviceEnrollmentChallengeId::new();
    let candidate_device_id = DeviceId::new();
    let capability = [36_u8; 32];
    let issued_at = UtcMillis::new(1_900)?;
    let expires_at = UtcMillis::new(3_000)?;
    let (request_body, exact_signed_request) = history_recovery_request_body(
        &candidate,
        request_id,
        identity_id,
        candidate_device_id,
        recipient_encryption_key,
        observed_head,
        issued_at,
        expires_at,
        capability,
    )?;

    let created = send_device_enrollment_challenge(
        app.clone(),
        REQUEST_KEY,
        HISTORY_RECOVERY_REQUEST_CONTENT_TYPE,
        request_body.clone(),
    )
    .await?;
    assert_eq!(created.status(), StatusCode::CREATED);
    let exact_receipt = to_bytes(created.into_body(), 16_384).await?.to_vec();
    assert_eq!(enrollment_challenge_id(&exact_receipt)?, request_id);

    let replay = send_device_enrollment_challenge(
        app.clone(),
        REQUEST_KEY,
        HISTORY_RECOVERY_REQUEST_CONTENT_TYPE,
        request_body.clone(),
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(replay.into_body(), 16_384).await?.to_vec(),
        exact_receipt
    );

    let changed_candidate = signing_key(37);
    let (changed_request, _) = history_recovery_request_body(
        &changed_candidate,
        DeviceEnrollmentChallengeId::new(),
        identity_id,
        DeviceId::new(),
        DeviceEncryptionPublicKey::try_from([38_u8; 32])?,
        observed_head,
        issued_at,
        expires_at,
        [39_u8; 32],
    )?;
    let changed_same_key = send_device_enrollment_challenge(
        app.clone(),
        REQUEST_KEY,
        HISTORY_RECOVERY_REQUEST_CONTENT_TYPE,
        changed_request,
    )
    .await?;
    assert_eq!(changed_same_key.status(), StatusCode::CONFLICT);
    assert_safe_error(changed_same_key, "IDEMPOTENCY_CONFLICT").await?;

    let same_request_different_key = send_device_enrollment_challenge(
        app,
        DIFFERENT_REQUEST_KEY,
        HISTORY_RECOVERY_REQUEST_CONTENT_TYPE,
        request_body,
    )
    .await?;
    assert_eq!(same_request_different_key.status(), StatusCode::CONFLICT);
    assert_safe_error(same_request_different_key, "IDEMPOTENCY_CONFLICT").await?;

    let rows: Vec<StoredHistoryRecoveryRequest> = sqlx::query_as(
        "SELECT protocol_version,recovery_request_bytes,request_digest,
                    recovery_request_digest,capability_hash,observed_head_sequence,
                    observed_head_hash
               FROM identity.device_enrollment_challenges WHERE identity_id=$1",
    )
    .bind(identity_id.to_string())
    .fetch_all(harness.identity_runtime_pool())
    .await?;
    assert_eq!(rows.len(), 1);
    let (
        protocol_version,
        stored_request,
        request_digest,
        recovery_request_digest,
        capability_hash,
        observed_head_sequence,
        observed_head_hash,
    ) = &rows[0];
    assert_eq!(*protocol_version, 2);
    assert_eq!(stored_request, &exact_signed_request);
    let CanonicalValue::Map(stored_fields) = decode_deterministic_cbor(stored_request)? else {
        return Err("stored history recovery request is not a map".into());
    };
    assert_eq!(stored_fields.len(), 12);
    for (index, (key, _)) in stored_fields.iter().enumerate() {
        assert_eq!(key, &CanonicalValue::Unsigned(u64::try_from(index + 1)?));
    }
    let expected_request_digest =
        Sha256Digest::hash_domain(HISTORY_RECOVERY_REQUEST_HASH_DOMAIN, &exact_signed_request);
    assert_eq!(
        request_digest.as_slice(),
        expected_request_digest.as_bytes()
    );
    assert_eq!(
        recovery_request_digest.as_slice(),
        expected_request_digest.as_bytes()
    );
    let expected_capability_hash =
        Sha256Digest::hash_domain(DEVICE_ENROLLMENT_CAPABILITY_HASH_DOMAIN, &capability);
    assert_eq!(
        capability_hash.as_slice(),
        expected_capability_hash.as_bytes()
    );
    assert_ne!(capability_hash.as_slice(), capability.as_slice());
    assert!(
        !stored_request
            .windows(capability.len())
            .any(|window| window == capability)
    );
    assert_eq!(
        *observed_head_sequence,
        i64::try_from(observed_head.sequence().get())?
    );
    assert_eq!(
        observed_head_hash.as_slice(),
        observed_head.hash().as_bytes()
    );
    Ok(())
}
