#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL boundary test keeps authentication classification non-oracular"
)]
async fn postgres_push_registration_observation_is_readonly_fenced_and_fail_closed()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let identity_repository = IdentityLogRepository::new();
    let session_repository = DeviceSessionRepository;
    let root = key(81);
    let recovery = key(82);
    let device_signing = key(83);
    let genesis_event = genesis(&root, &recovery);
    let identity_id = genesis_event.identity_id();
    let head1 = committed(
        identity_repository
            .append(
                &store,
                &append_command(81, None, &genesis_event)?,
                at(1_001),
            )
            .await?,
    )?;
    let device_id = DeviceId::from_str(AUTHORITY_DEVICE)?;
    let add = device_add(
        &root,
        identity_id,
        device_id,
        &device_signing,
        81,
        2,
        head1.hash(),
        1_010,
    );
    let head2 = committed(
        identity_repository
            .append(&store, &append_command(82, Some(head1), &add)?, at(1_011))
            .await?,
    )?;
    let credential = session(
        &store,
        identity_id,
        device_id,
        &device_signing,
        83,
        at(2_000),
    )
    .await?;

    let observation = session_repository
        .authenticate_push_registration_readonly(&store, &credential, at(2_100))
        .await?;
    assert_eq!(observation.identity_id(), identity_id);
    assert_eq!(observation.device_id(), device_id);
    assert_eq!(observation.signing_key(), public(&device_signing));
    assert_eq!(observation.head(), head2);

    let wrong = DeviceSessionCredential::new(credential.session_id(), [99; 32])?;
    assert!(matches!(
        session_repository
            .authenticate_push_registration_readonly(&store, &wrong, at(2_100))
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));
    assert!(matches!(
        session_repository
            .authenticate_push_registration_readonly(
                &store,
                &credential,
                at(2_000 + 15 * 60 * 1_000)
            )
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));

    let revoke = signed_event(
        &root,
        identity_id,
        3,
        Some(head2.hash()),
        2_200,
        IdentityLogEventPayloadV1::DeviceRevoke { device_id },
    );
    let head3 = committed(
        identity_repository
            .append(
                &store,
                &append_command(84, Some(head2), &revoke)?,
                at(2_201),
            )
            .await?,
    )?;
    assert_ne!(head3, observation.head());
    assert!(matches!(
        session_repository
            .authenticate_push_registration_readonly(&store, &wrong, at(2_300))
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));
    assert!(matches!(
        session_repository
            .authenticate_push_registration_readonly(&store, &credential, at(2_300))
            .await,
        Err(IdentityPersistenceError::DeviceSessionRevoked)
    ));
    assert!(matches!(
        session_repository
            .authenticate_push_registration_readonly(
                &store,
                &credential,
                at(2_000 + 15 * 60 * 1_000)
            )
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL boundary test keeps retention and terminal identity-state rejection coupled"
)]
async fn postgres_push_registration_observation_rejects_pruned_forked_and_tombstoned_state()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let repository = IdentityLogRepository::new();
    let sessions = DeviceSessionRepository;
    let root = key(84);
    let recovery = key(85);
    let signing = key(86);
    let genesis_event = genesis(&root, &recovery);
    let identity_id = genesis_event.identity_id();
    let head1 = committed(
        repository
            .append(
                &store,
                &append_command(85, None, &genesis_event)?,
                at(1_001),
            )
            .await?,
    )?;
    let device_id = DeviceId::from_str(PROVIDER_DEVICE)?;
    let add = device_add(
        &root,
        identity_id,
        device_id,
        &signing,
        82,
        2,
        head1.hash(),
        1_010,
    );
    let _head2 = committed(
        repository
            .append(&store, &append_command(86, Some(head1), &add)?, at(1_011))
            .await?,
    )?;
    let credential = session(&store, identity_id, device_id, &signing, 87, at(2_000)).await?;

    let pruned: i64 = sqlx::query_scalar("SELECT identity.prune_expired_device_sessions($1, 1)")
        .bind(2_000 + 15 * 60 * 1_000)
        .fetch_one(harness.admin_pool())
        .await?;
    assert!(pruned >= 1);
    assert!(matches!(
        sessions
            .authenticate_push_registration_readonly(&store, &credential, at(2_100))
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));

    let credential = session(&store, identity_id, device_id, &signing, 88, at(3_000)).await?;
    let current_head = sessions
        .authenticate_push_registration_readonly(&store, &credential, at(3_100))
        .await?
        .head();
    let left = relay_event(
        &root,
        identity_id,
        3,
        current_head.hash(),
        "fork-left",
        3_200,
    );
    let right = relay_event(
        &root,
        identity_id,
        3,
        current_head.hash(),
        "fork-right",
        3_201,
    );
    let left_command = append_command(89, Some(current_head), &left)?;
    let right_command = append_command(90, Some(current_head), &right)?;
    let (left, right) = tokio::join!(
        repository.append(&store, &left_command, at(3_210)),
        repository.append(&store, &right_command, at(3_211)),
    );
    assert!(matches!(
        (left?, right?),
        (
            IdentityAppendOutcome::Committed(_),
            IdentityAppendOutcome::Forked { .. }
        ) | (
            IdentityAppendOutcome::Forked { .. },
            IdentityAppendOutcome::Committed(_)
        )
    ));
    assert!(matches!(
        sessions
            .authenticate_push_registration_readonly(&store, &credential, at(3_100))
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));

    let tombstone_root = key(92);
    let tombstone_recovery = key(93);
    let tombstone_signing = key(94);
    let tombstone_genesis = genesis(&tombstone_root, &tombstone_recovery);
    let tombstone_identity = tombstone_genesis.identity_id();
    let tombstone_head1 = committed(
        repository
            .append(
                &store,
                &append_command(91, None, &tombstone_genesis)?,
                at(4_001),
            )
            .await?,
    )?;
    let tombstone_device = DeviceId::from_str(SECOND_CANDIDATE_DEVICE)?;
    let tombstone_add = device_add(
        &tombstone_root,
        tombstone_identity,
        tombstone_device,
        &tombstone_signing,
        84,
        2,
        tombstone_head1.hash(),
        4_010,
    );
    committed(
        repository
            .append(
                &store,
                &append_command(92, Some(tombstone_head1), &tombstone_add)?,
                at(4_011),
            )
            .await?,
    )?;
    let tombstone_credential = session(
        &store,
        tombstone_identity,
        tombstone_device,
        &tombstone_signing,
        95,
        at(5_000),
    )
    .await?;
    sqlx::query("UPDATE identity.log_heads SET state='tombstoned' WHERE identity_id=$1")
        .bind(tombstone_identity.to_string())
        .execute(harness.admin_pool())
        .await?;
    assert!(matches!(
        sessions
            .authenticate_push_registration_readonly(&store, &tombstone_credential, at(5_100))
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL boundary test couples immutable session binding, snapshot locks, and writer progress"
)]
async fn postgres_push_registration_observation_preserves_binding_and_never_blocks_relay_append()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let repository = IdentityLogRepository::new();
    let sessions = DeviceSessionRepository;
    let root = key(89);
    let recovery = key(90);
    let signing = key(91);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let head1 = committed(
        repository
            .append(&store, &append_command(89, None, &genesis)?, at(1_001))
            .await?,
    )?;
    let device_id = DeviceId::from_str(CANDIDATE_DEVICE)?;
    let add = device_add(
        &root,
        identity_id,
        device_id,
        &signing,
        83,
        2,
        head1.hash(),
        1_010,
    );
    let head2 = committed(
        repository
            .append(&store, &append_command(90, Some(head1), &add)?, at(1_011))
            .await?,
    )?;
    let credential = session(&store, identity_id, device_id, &signing, 91, at(2_000)).await?;
    let before_sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM identity.device_sessions")
        .fetch_one(harness.admin_pool())
        .await?;
    let before_receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM identity.device_session_receipts")
            .fetch_one(harness.admin_pool())
            .await?;

    let update = sqlx::query(
        "UPDATE identity.device_sessions SET expires_at_ms=expires_at_ms+1 WHERE session_id=$1",
    )
    .bind(*credential.session_id().as_uuid())
    .execute(harness.admin_pool())
    .await
    .expect_err("session rows must be immutable outside retention");
    assert_eq!(
        update
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        Some("23514".into())
    );

    let mut observation_tx = store.begin_readonly_repeatable().await?;
    let observed = DeviceSessionRepository::authenticate_push_registration_readonly_in_transaction(
        observation_tx.connection(),
        &credential,
        at(2_100),
    )
    .await?;
    assert_eq!(observed.head(), head2);
    let observer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(observation_tx.connection())
        .await?;
    let forbidden_locks: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_locks WHERE pid=$1 AND locktype IN ('advisory', 'tuple')",
    )
    .bind(observer_pid)
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(forbidden_locks, 0);

    let relay = relay_event(
        &root,
        identity_id,
        3,
        head2.hash(),
        "push-observation",
        2_200,
    );
    let writer_store = store.clone();
    let writer = tokio::spawn(async move {
        IdentityLogRepository::new()
            .append(
                &writer_store,
                &append_command(92, Some(head2), &relay)?,
                at(2_201),
            )
            .await
    });
    let advanced = tokio::time::timeout(Duration::from_secs(2), writer)
        .await
        .map_err(|_| "identity writer was blocked by read-only observation")???;
    let advanced = committed(advanced)?;
    assert_ne!(advanced, observed.head());
    observation_tx.commit().await?;

    let fresh = sessions
        .authenticate_push_registration_readonly(&store, &credential, at(2_300))
        .await?;
    assert_eq!(fresh.identity_id(), observed.identity_id());
    assert_eq!(fresh.device_id(), observed.device_id());
    assert_eq!(fresh.signing_key(), observed.signing_key());
    assert_eq!(fresh.head(), advanced);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity.device_sessions")
            .fetch_one(harness.admin_pool())
            .await?,
        before_sessions
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM identity.device_session_receipts")
            .fetch_one(harness.admin_pool())
            .await?,
        before_receipts
    );
    Ok(())
}
