#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one two-node boundary test proves remote log authentication, exact replay, revocation, and one-time consumption together"
)]
async fn federated_key_package_claim_uses_current_remote_device_proof_and_consumes_once()
-> Result<(), Box<dyn Error>> {
    let target_harness = support::PostgresHarness::start().await?;
    let target_store =
        IdentityPgStore::connect(target_harness.identity_runtime_options(), 4).await?;
    let publisher = enroll_active_device(&target_store, 111, 112, 113, [114; 32]).await?;

    // Keep the requester identity authoritative only at its own origin. The
    // target database deliberately never receives a copy of this log.
    let requester_root = SigningKey::from_bytes(&[101; 32]);
    let requester_recovery = SigningKey::from_bytes(&[102; 32]);
    let requester_device = SigningKey::from_bytes(&[103; 32]);
    let requester_genesis = genesis(&requester_root, &requester_recovery, 1_000)?;
    let requester_identity_id = requester_genesis.identity_id();
    let requester_device_id = DeviceId::new();
    let requester_initial = device_add(
        &requester_root,
        &requester_device,
        requester_identity_id,
        requester_device_id,
        requester_genesis.entry_hash()?,
        2,
        1_100,
    )?;
    let requester_head_hash = requester_initial.entry_hash()?;
    let requester_genesis_exact = requester_genesis.to_deterministic_cbor()?;
    let requester_initial_exact = requester_initial.to_deterministic_cbor()?;
    let requester = ActiveDevice {
        root: requester_root,
        device: requester_device,
        identity_id: requester_identity_id,
        device_id: requester_device_id,
        head_sequence: SafeUint::new(2)?,
        head_hash: requester_head_hash,
        session_id: DeviceSessionId::new(),
        session_secret: [0; 32],
    };
    let requester_page = Arc::new(tokio::sync::RwLock::new(
        IdentityLogPageV1::new(
            requester.identity_id,
            requester.head_sequence,
            requester.head_hash,
            0,
            vec![
                requester_genesis_exact.clone(),
                requester_initial_exact.clone(),
            ],
            2,
            false,
        )?
        .to_deterministic_cbor()?,
    ));

    let requester_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let requester_origin = format!("http://{}", requester_listener.local_addr()?);
    let requester_app = axum::Router::new().route(
        "/v1/identities/{identity_id}/log",
        axum::routing::get({
            let requester_page = Arc::clone(&requester_page);
            move || {
                let requester_page = Arc::clone(&requester_page);
                async move {
                    (
                        StatusCode::OK,
                        [
                            (
                                header::CONTENT_TYPE,
                                "application/vnd.dirextalk.identity-log-page.v1+cbor",
                            ),
                            (header::CACHE_CONTROL, "no-store"),
                            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                        ],
                        requester_page.read().await.clone(),
                    )
                }
            }
        }),
    );
    let requester_server = tokio::spawn(async move {
        let _ = axum::serve(requester_listener, requester_app).await;
    });

    let target_app = identity_bootstrap_router_with_state(
        IdentityBootstrapState::with_clock_and_device_session_audience(
            target_store.clone(),
            Arc::new(FixedClock(2_000)),
            AUDIENCE,
        )
        .with_federated_identity_configuration(
            "https://x4.identity.test",
            [requester_origin.clone()],
            None,
        )?,
    );
    let package_id = KeyPackageId::new();
    let publish_body = key_package_publish_body(
        &publisher.device,
        publisher.identity_id,
        publisher.device_id,
        package_id,
        publisher.head_sequence,
        publisher.head_hash,
        UtcMillis::new(600_000)?,
        &[0xc1, 0xa1, 0x13],
    )?;
    let publish_response = send_key_package_publish(
        target_app.clone(),
        "federated-publish-0001",
        publisher.session_id,
        publisher.session_secret,
        package_id,
        publish_body.clone(),
    )
    .await?;
    assert_eq!(publish_response.status(), StatusCode::CREATED);

    let claim_body = key_package_claim_body(publisher.identity_id, publisher.device_id)?;
    let proof = federated_key_package_claim_proof(
        &requester,
        &requester_origin,
        publisher.identity_id,
        publisher.device_id,
        &claim_body,
        "federated-claim-0001",
        [0x91; 32],
    )?;
    let first = send_federated_key_package_claim(
        target_app.clone(),
        &requester_origin,
        "federated-claim-0001",
        &proof,
        claim_body.clone(),
    )
    .await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    assert_eq!(
        to_bytes(first.into_body(), 131_072).await?.to_vec(),
        publish_body
    );

    // Simulate a lost success response by replaying the byte-identical proof,
    // body, and idempotency key. The original consumed envelope is recovered.
    let replay = send_federated_key_package_claim(
        target_app.clone(),
        &requester_origin,
        "federated-claim-0001",
        &proof,
        claim_body.clone(),
    )
    .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(replay.into_body(), 131_072).await?.to_vec(),
        publish_body
    );

    let second_proof = federated_key_package_claim_proof(
        &requester,
        &requester_origin,
        publisher.identity_id,
        publisher.device_id,
        &claim_body,
        "federated-claim-0002",
        [0x92; 32],
    )?;
    let exhausted = send_federated_key_package_claim(
        target_app.clone(),
        &requester_origin,
        "federated-claim-0002",
        &second_proof,
        claim_body.clone(),
    )
    .await?;
    assert_eq!(exhausted.status(), StatusCode::NOT_FOUND);
    assert_safe_error(exhausted, "KEY_PACKAGE_UNAVAILABLE").await?;

    let target_claims: i64 = sqlx::query_scalar("SELECT count(*) FROM identity.key_package_claims")
        .fetch_one(target_harness.identity_runtime_pool())
        .await?;
    let target_requester_logs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.log_heads WHERE identity_id=$1")
            .bind(requester.identity_id.to_string())
            .fetch_one(target_harness.identity_runtime_pool())
            .await?;
    assert_eq!(target_claims, 1);
    assert_eq!(target_requester_logs, 0);

    let requester_revoke = signed_event(
        &requester.root,
        requester.identity_id,
        3,
        Some(requester.head_hash),
        1_950,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: requester.device_id,
        },
    )?;
    *requester_page.write().await = IdentityLogPageV1::new(
        requester.identity_id,
        SafeUint::new(3)?,
        requester_revoke.entry_hash()?,
        0,
        vec![
            requester_genesis_exact,
            requester_initial_exact,
            requester_revoke.to_deterministic_cbor()?,
        ],
        3,
        false,
    )?
    .to_deterministic_cbor()?;
    let revoked_replay = send_federated_key_package_claim(
        target_app,
        &requester_origin,
        "federated-claim-0001",
        &proof,
        claim_body,
    )
    .await?;
    assert_eq!(revoked_replay.status(), StatusCode::UNAUTHORIZED);
    assert_safe_error(revoked_replay, "DEVICE_AUTHENTICATION_FAILED").await?;

    requester_server.abort();
    Ok(())
}
