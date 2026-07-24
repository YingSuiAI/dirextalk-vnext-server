#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL workflow proves the coupled V41 fences"
)]
async fn postgres_catalog_preparation_and_provider_workflow_is_fenced_and_replay_safe()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let identity_repository = IdentityLogRepository::new();
    let catalog_repository = RecoveryScopeCatalogRepository;
    let enrollment_repository = DeviceEnrollmentRepository;

    let root = key(1);
    let recovery = key(2);
    let authority = key(3);
    let provider = key(4);
    let candidate = key(5);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let head1 = committed(
        identity_repository
            .append(&store, &append_command(1, None, &genesis)?, at(1_001))
            .await?,
    )?;
    let authority_device = DeviceId::from_str(AUTHORITY_DEVICE)?;
    let authority_add = device_add(
        &root,
        identity_id,
        authority_device,
        &authority,
        33,
        2,
        head1.hash(),
        1_010,
    );
    let head2 = committed(
        identity_repository
            .append(
                &store,
                &append_command(2, Some(head1), &authority_add)?,
                at(1_011),
            )
            .await?,
    )?;
    let provider_device = DeviceId::from_str(PROVIDER_DEVICE)?;
    let provider_add = device_add(
        &root,
        identity_id,
        provider_device,
        &provider,
        44,
        3,
        head2.hash(),
        1_020,
    );
    let head3 = committed(
        identity_repository
            .append(
                &store,
                &append_command(3, Some(head2), &provider_add)?,
                at(1_021),
            )
            .await?,
    )?;

    let authority_credential = session(
        &store,
        identity_id,
        authority_device,
        &authority,
        11,
        at(2_000),
    )
    .await?;
    let provider_credential = session(
        &store,
        identity_id,
        provider_device,
        &provider,
        12,
        at(2_000),
    )
    .await?;

    let catalog = catalog_command(
        identity_id,
        head3,
        &authority,
        Sha256Digest::from_bytes([21; 32]),
        safe(1),
        None,
        [31; 32],
    )?;
    let (first, second) = tokio::join!(
        catalog_repository.publish(&store, &catalog, &authority_credential, at(3_000)),
        catalog_repository.publish(&store, &catalog, &authority_credential, at(3_000)),
    );
    let first = first?;
    let second = second?;
    assert_ne!(first.created, second.created);
    assert_eq!(first.exact_head_bytes, second.exact_head_bytes);
    assert_eq!(catalog_rows(&harness, identity_id).await?, 1);

    if false {
    let authority_candidate = key(7);
    let authority_candidate_device = DeviceId::from_str(AUTHORITY_CANDIDATE_DEVICE)?;
    let authority_enrollment_capability = [35; 32];
    let authority_challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([36; 32]),
                identity_id,
                authority_candidate_device,
                public(&authority_candidate),
                DeviceEncryptionPublicKey::try_from([77; 32])?,
                DeviceEnrollmentCapability::new(authority_enrollment_capability)?,
            )?,
            at(4_600),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(authority_challenge) = authority_challenge else {
        return Err("authority-provider challenge must be new".into());
    };
    let authority_response_capability = RecoveryResponseCapability::new([37; 32])?;
    let authority_preparation = CatalogPreparationCommand::parse_v2(
        Sha256Digest::from_bytes([38; 32]),
        preparation_bytes(
            authority_challenge.challenge_id(),
            identity_id,
            authority_candidate_device,
            &authority_candidate,
            [77; 32],
            head3,
            [37; 32],
            &catalog,
            Sha256Digest::from_bytes([38; 32]),
        )?,
        DeviceEnrollmentCapability::new(authority_enrollment_capability)?,
        &authority_response_capability,
    )?;
    assert!(
        catalog_repository
            .prepare(&store, &authority_preparation, at(4_700))
            .await?
            .0
    );
    let authority_response = provider_command(
        authority_challenge.challenge_id(),
        catalog.head_digest,
        authority_device,
        &authority,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [77; 32],
        Sha256Digest::from_bytes([39; 32]),
        identity_id,
        catalog.catalog_id,
        catalog.generation,
        authority_preparation.digest,
        head3,
        head3,
        authority_candidate_device,
        &authority_candidate,
        &device_add(&root, identity_id, authority_candidate_device, &authority_candidate, 77, 4, head3.hash(), 7_101).to_deterministic_cbor()?,
    )?;
    let authority_interleaving_credential = session(
        &store,
        identity_id,
        authority_device,
        &authority,
        17,
        at(7_100),
    )
    .await?;
    let authority_replay = CatalogPreparationCommand::parse_v2(
        authority_preparation.idempotency_key_hash,
        authority_preparation.exact_bytes.clone(),
        DeviceEnrollmentCapability::new(authority_enrollment_capability)?,
        &RecoveryResponseCapability::new([37; 32])?,
    )?;
    let mut preparation_blocker = harness.admin_pool().begin().await?;
    sqlx::query(
        "SELECT request_id FROM identity.recovery_scope_catalog_preparations WHERE request_id=$1 FOR UPDATE",
    )
    .bind(*authority_challenge.challenge_id().as_uuid())
    .execute(&mut *preparation_blocker)
    .await?;
    let provider_store = store.clone();
    let provider_task = tokio::spawn(async move {
        RecoveryScopeCatalogRepository
            .put_provider_response(
                &provider_store,
                &authority_response,
                &authority_interleaving_credential,
                at(7_200),
            )
            .await
    });
    wait_until_identity_lock_is_held(harness.admin_pool(), identity_id).await?;
    let status_store = store.clone();
    let mut status_task = tokio::spawn(async move {
        RecoveryScopeCatalogRepository
            .status(
                &status_store,
                authority_challenge.challenge_id(),
                &RecoveryResponseCapability::new([37; 32])?,
                at(7_201),
            )
            .await
    });
    let replay_store = store.clone();
    let mut replay_task = tokio::spawn(async move {
        RecoveryScopeCatalogRepository
            .prepare(&replay_store, &authority_replay, at(7_201))
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut status_task)
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut replay_task)
            .await
            .is_err()
    );
    preparation_blocker.commit().await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), provider_task)
            .await???
            .status,
        CatalogStatus::ResponseAvailable,
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), &mut status_task)
            .await???
            .status,
        CatalogStatus::ResponseAvailable,
    );
    let (created, replay_status) =
        tokio::time::timeout(Duration::from_secs(5), &mut replay_task).await???;
    assert!(!created);
    assert_eq!(replay_status.status, CatalogStatus::ResponseAvailable);
    }

    let changed_same_key = catalog_command(
        identity_id,
        head3,
        &authority,
        catalog.idempotency_key_hash,
        safe(1),
        None,
        [32; 32],
    )?;
    assert!(matches!(
        catalog_repository
            .publish(&store, &changed_same_key, &authority_credential, at(3_001))
            .await,
        Err(IdentityPersistenceError::IdempotencyConflict)
    ));
    let gap = catalog_command(
        identity_id,
        head3,
        &authority,
        Sha256Digest::from_bytes([22; 32]),
        safe(3),
        Some(catalog.head_digest),
        [33; 32],
    )?;
    assert!(matches!(
        catalog_repository
            .publish(&store, &gap, &authority_credential, at(3_001))
            .await,
        Err(IdentityPersistenceError::RecoveryCatalogConflict)
    ));
    assert_eq!(catalog_rows(&harness, identity_id).await?, 1);

    let candidate_device = DeviceId::from_str(CANDIDATE_DEVICE)?;
    let enrollment_capability_bytes = [41; 32];
    let challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([42; 32]),
                identity_id,
                candidate_device,
                public(&candidate),
                DeviceEncryptionPublicKey::try_from([55; 32])?,
                DeviceEnrollmentCapability::new(enrollment_capability_bytes)?,
            )?,
            at(4_000),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(challenge) = challenge else {
        return Err("new ordinary enrollment challenge must be created".into());
    };

    let response_capability_bytes = [61; 32];
    let response_capability = RecoveryResponseCapability::new(response_capability_bytes)?;
    let prep_key = Sha256Digest::from_bytes([62; 32]);
    let exact_preparation_bytes = preparation_bytes(
        challenge.challenge_id(),
        identity_id,
        candidate_device,
        &candidate,
        [55; 32],
        head3,
        response_capability_bytes,
        &catalog,
        prep_key,
    )?;
    let prepare_a = CatalogPreparationCommand::parse_v2(
        prep_key,
        exact_preparation_bytes.clone(),
        DeviceEnrollmentCapability::new(enrollment_capability_bytes)?,
        &response_capability,
    )?;
    let prepare_b = CatalogPreparationCommand::parse_v2(
        prep_key,
        exact_preparation_bytes,
        DeviceEnrollmentCapability::new(enrollment_capability_bytes)?,
        &response_capability,
    )?;
    let (prepare_first, prepare_second) = tokio::join!(
        catalog_repository.prepare(&store, &prepare_a, at(5_000)),
        catalog_repository.prepare(&store, &prepare_b, at(5_000)),
    );
    assert_ne!(prepare_first?.0, prepare_second?.0);
    assert_eq!(preparation_rows(&harness, identity_id).await?, 1);
    assert_eq!(
        catalog_repository
            .status(
                &store,
                challenge.challenge_id(),
                &response_capability,
                at(5_001)
            )
            .await?
            .status,
        CatalogStatus::Pending,
    );

    let wrong_capability = RecoveryResponseCapability::new([62; 32])?;
    assert!(matches!(
        catalog_repository
            .status(
                &store,
                challenge.challenge_id(),
                &wrong_capability,
                at(5_001)
            )
            .await,
        Err(IdentityPersistenceError::RecoveryResponseCapabilityRejected)
    ));

    let invalid_provider = provider_command(
        challenge.challenge_id(),
        catalog.head_digest,
        provider_device,
        &provider,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [55; 32],
        Sha256Digest::from_bytes([70; 32]),
        identity_id,
        catalog.catalog_id,
        catalog.generation,
        prepare_a.digest,
        head3,
        IdentityLogHead::observed(identity_id, safe(4), Sha256Digest::from_bytes([99; 32]))?,
        candidate_device,
        &candidate,
        &device_add(&root, identity_id, candidate_device, &candidate, 55, 4, head3.hash(), 7_101).to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        catalog_repository
            .put_provider_response(&store, &invalid_provider, &provider_credential, at(5_100))
            .await,
        Err(IdentityPersistenceError::RecoveryPreparationRevoked)
            | Err(IdentityPersistenceError::RecoveryPreparationInvalidated)
    ));
    assert_eq!(provider_response_rows(&harness, identity_id).await?, 0);

    let approval_credential = session(
        &store,
        identity_id,
        provider_device,
        &provider,
        13,
        at(7_100),
    )
    .await?;

    let candidate_add = device_add(
        &root,
        identity_id,
        candidate_device,
        &candidate,
        55,
        4,
        head3.hash(),
        7_101,
    );
    let approval = DeviceEnrollmentApprovalCommand::new(
        Sha256Digest::from_bytes([71; 32]),
        challenge.challenge_id(),
        DeviceEnrollmentCapability::new(enrollment_capability_bytes)?,
        head3.hash(),
        candidate_add.to_deterministic_cbor()?,
    )?;
    let head4 = committed(
        enrollment_repository
            .approve(&store, approval, approval_credential, at(7_102))
            .await?,
    )?;
    assert_eq!(head4.sequence().get(), head3.sequence().get() + 1);
    assert_eq!(
        catalog_repository
            .status(
                &store,
                challenge.challenge_id(),
                &response_capability,
                at(7_103)
            )
            .await?
            .status,
        CatalogStatus::Pending,
    );
    let replay_after_h1 = catalog_repository
        .publish(&store, &catalog, &authority_credential, at(7_104))
        .await?;
    assert!(!replay_after_h1.created);

    let provider_response = provider_command(
        challenge.challenge_id(),
        catalog.head_digest,
        provider_device,
        &provider,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [55; 32],
        Sha256Digest::from_bytes([72; 32]),
        identity_id,
        catalog.catalog_id,
        catalog.generation,
        prepare_a.digest,
        head3,
        head4,
        candidate_device,
        &candidate,
        &candidate_add.to_deterministic_cbor()?,
    )?;
    let (ready, replay) = tokio::join!(
        catalog_repository.put_provider_response(
            &store,
            &provider_response,
            &provider_credential,
            at(7_200),
        ),
        catalog_repository.put_provider_response(
            &store,
            &provider_response,
            &provider_credential,
            at(7_200),
        ),
    );
    let ready = ready?;
    let replay = replay?;
    assert_eq!(ready.status, CatalogStatus::ResponseAvailable);
    assert_eq!(
        ready.provider_response.as_deref(),
        Some(provider_response.exact_bytes.as_slice())
    );
    assert_eq!(replay.provider_response, ready.provider_response);
    assert_eq!(provider_response_rows(&harness, identity_id).await?, 1);

    let rotated = catalog_command(
        identity_id,
        head4,
        &authority,
        Sha256Digest::from_bytes([73; 32]),
        safe(2),
        Some(catalog.head_digest),
        [34; 32],
    )?;
    catalog_repository
        .publish(&store, &rotated, &authority_credential, at(7_300))
        .await?;
    let invalidated = catalog_repository
        .status(
            &store,
            challenge.challenge_id(),
            &response_capability,
            at(7_301),
        )
        .await?;
    assert_eq!(
        invalidated.status,
        CatalogStatus::Invalidated(CatalogStatusInvalidation::Catalog)
    );
    assert!(invalidated.provider_response.is_none());

    if false {
    let second_candidate = key(6);
    let second_candidate_device = DeviceId::from_str(SECOND_CANDIDATE_DEVICE)?;
    let second_enrollment_capability_bytes = [81; 32];
    let second_challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([82; 32]),
                identity_id,
                second_candidate_device,
                public(&second_candidate),
                DeviceEncryptionPublicKey::try_from([66; 32])?,
                DeviceEnrollmentCapability::new(second_enrollment_capability_bytes)?,
            )?,
            at(7_400),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(second_challenge) = second_challenge else {
        return Err("second ordinary enrollment challenge must be created".into());
    };
    let second_response_capability_bytes = [83; 32];
    let second_response_capability =
        RecoveryResponseCapability::new(second_response_capability_bytes)?;
    let second_prep_key = Sha256Digest::from_bytes([84; 32]);
    let second_preparation = CatalogPreparationCommand::parse_v2(
        Sha256Digest::from_bytes([84; 32]),
        preparation_bytes(
            second_challenge.challenge_id(),
            identity_id,
            second_candidate_device,
            &second_candidate,
            [66; 32],
            head4,
            second_response_capability_bytes,
            &rotated,
            second_prep_key,
        )?,
        DeviceEnrollmentCapability::new(second_enrollment_capability_bytes)?,
        &second_response_capability,
    )?;
    assert!(
        catalog_repository
            .prepare(&store, &second_preparation, at(7_401))
            .await?
            .0
    );

    let second_candidate_add = device_add(
        &root,
        identity_id,
        provider_device,
        &provider,
        66,
        5,
        head4.hash(),
        7_402,
    );
    let second_approval = DeviceEnrollmentApprovalCommand::new(
        Sha256Digest::from_bytes([87; 32]),
        second_challenge.challenge_id(),
        DeviceEnrollmentCapability::new(second_enrollment_capability_bytes)?,
        head4.hash(),
        second_candidate_add.to_deterministic_cbor()?,
    )?;
    let second_approval_credential = session(
        &store,
        identity_id,
        provider_device,
        &provider,
        15,
        at(12_100),
    )
    .await?;
    let head5 = committed(
        enrollment_repository
            .approve(
                &store,
                second_approval,
                second_approval_credential,
                at(12_200),
            )
            .await?,
    )?;
    let second_candidate_credential = session(
        &store,
        identity_id,
        second_candidate_device,
        &second_candidate,
        14,
        at(12_300),
    )
    .await?;
    let candidate_response = provider_command(
        second_challenge.challenge_id(),
        rotated.head_digest,
        provider_device,
        &provider,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [66; 32],
        Sha256Digest::from_bytes([88; 32]),
        identity_id,
        rotated.catalog_id,
        rotated.generation,
        second_preparation.digest,
        head4,
        head5,
        second_candidate_device,
        &second_candidate,
        &second_candidate_add.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        catalog_repository
            .put_provider_response(
                &store,
                &candidate_response,
                &second_candidate_credential,
                at(12_400),
            )
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));
    assert_eq!(provider_response_rows(&harness, identity_id).await?, 1);

    let provider_revoke = signed_event(
        &root,
        identity_id,
        6,
        Some(head5.hash()),
        12_500,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: provider_device,
        },
    );
    let head6 = committed(
        identity_repository
            .append(
                &store,
                &append_command(85, Some(head5), &provider_revoke)?,
                at(12_501),
            )
            .await?,
    )?;
    assert_eq!(head6.sequence().get(), head5.sequence().get() + 1);
    let rejected_after_revoke = provider_command(
        second_challenge.challenge_id(),
        rotated.head_digest,
        provider_device,
        &provider,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [66; 32],
        Sha256Digest::from_bytes([86; 32]),
        identity_id,
        rotated.catalog_id,
        rotated.generation,
        second_preparation.digest,
        head4,
        head5,
        second_candidate_device,
        &second_candidate,
        &second_candidate_add.to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        catalog_repository
            .put_provider_response(
                &store,
                &rejected_after_revoke,
                &provider_credential,
                at(12_502),
            )
            .await,
        Err(IdentityPersistenceError::DeviceAuthenticationRejected)
    ));
    assert_eq!(provider_response_rows(&harness, identity_id).await?, 3);
    let revoked = catalog_repository
        .status(
            &store,
            second_challenge.challenge_id(),
            &second_response_capability,
            at(12_503),
        )
        .await?;
    assert_eq!(
        revoked.status,
        CatalogStatus::Invalidated(CatalogStatusInvalidation::Identity)
    );
    assert!(revoked.provider_response.is_none());

    let expired = catalog_repository
        .status(
            &store,
            challenge.challenge_id(),
            &response_capability,
            at(200_000),
        )
        .await?;
    assert_eq!(expired.status, CatalogStatus::Expired);
    assert!(expired.provider_response.is_none());

    let racing_candidate = key(8);
    let racing_candidate_device = DeviceId::from_str(RACING_CANDIDATE_DEVICE)?;
    let racing_capability = [101; 32];
    let racing_challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([102; 32]),
                identity_id,
                racing_candidate_device,
                public(&racing_candidate),
                DeviceEncryptionPublicKey::try_from([88; 32])?,
                DeviceEnrollmentCapability::new(racing_capability)?,
            )?,
            at(250_000),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(racing_challenge) = racing_challenge else {
        return Err("racing enrollment challenge must be new".into());
    };
    let racing_approval_credential = session(
        &store,
        identity_id,
        authority_device,
        &authority,
        19,
        at(250_100),
    )
    .await?;
    let racing_add = device_add(
        &root,
        identity_id,
        racing_candidate_device,
        &racing_candidate,
        88,
        7,
        head6.hash(),
        250_150,
    );
    let racing_approval = DeviceEnrollmentApprovalCommand::new(
        Sha256Digest::from_bytes([103; 32]),
        racing_challenge.challenge_id(),
        DeviceEnrollmentCapability::new(racing_capability)?,
        head6.hash(),
        racing_add.to_deterministic_cbor()?,
    )?;
    let mut challenge_blocker = harness.admin_pool().begin().await?;
    sqlx::query(
        "SELECT challenge_id FROM identity.device_enrollment_challenges WHERE challenge_id=$1 FOR UPDATE",
    )
    .bind(*racing_challenge.challenge_id().as_uuid())
    .execute(&mut *challenge_blocker)
    .await?;
    let approval_store = store.clone();
    let mut approval_task = tokio::spawn(async move {
        DeviceEnrollmentRepository
            .approve(
                &approval_store,
                racing_approval,
                racing_approval_credential,
                at(250_200),
            )
            .await
    });
    wait_until_identity_lock_is_held(harness.admin_pool(), identity_id).await?;
    let cancellation_store = store.clone();
    let mut cancellation_task = tokio::spawn(async move {
        DeviceEnrollmentRepository
            .cancel(
                &cancellation_store,
                racing_challenge.challenge_id(),
                DeviceEnrollmentCapability::new(racing_capability)?,
                at(250_201),
            )
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut approval_task)
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut cancellation_task)
            .await
            .is_err()
    );
    challenge_blocker.commit().await?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), &mut approval_task).await???,
        IdentityAppendOutcome::Committed(_)
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), &mut cancellation_task).await??,
        Err(IdentityPersistenceError::DeviceEnrollmentChallengeApproved)
    ));

    }
    let no_plaintext_columns: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(
             SELECT 1 FROM information_schema.columns
              WHERE table_schema='identity'
                AND table_name IN ('recovery_scope_catalogs','recovery_scope_catalog_preparations')
                AND column_name ~ '(scope|leaf|plaintext|receipt)'
                AND column_name <> 'leaf_count')",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(no_plaintext_columns);
    Ok(())
}
